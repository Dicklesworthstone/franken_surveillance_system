#![forbid(unsafe_code)]
//! Integration contract tests for CAP- fixtures RTSP transcript (fss-2h5zq.8).
//!
//! Verifies all eight committed RTSP/1.0 interleaved-TCP transcript fixtures in
//! `tests/fixtures/media/rtsp/`:
//! - byte-identical regeneration of every `.transcript` file and `fixture_manifest.json`
//!   against pinned SHA-256 digests;
//! - independent container record framing (header + exact sum of record lengths == file length);
//! - every C2S RTSP request carries a valid numeric `CSeq` header;
//! - zero `Authorization:` headers (case-insensitive) and zero IPv4/IPv6 literals in any record,
//!   SDP line, or RTCP CNAME (with negative controls proving the scanners trigger);
//! - SDP `sprop-parameter-sets` Base64 SPS/PPS independently decode to the exact SPS/PPS NAL
//!   bytes extracted independently from `tests/fixtures/media/h264/clean.264`;
//! - per-packet `fss_packet::SequenceClass` verification (including `Probation` -> `Baseline`
//!   -> `Advanced` across sequence wrap `65534 -> 65535 -> 0..12`) for every media-carrying
//!   variant including `interleave_split`, `sr_absent`, `rtcp_rsize`, and
//!   `get_parameter_keepalive`;
//! - independent RFC 3550 RTCP walker proving compound SR+SDES structure on default variants,
//!   SR-only structure (and `a=rtcp-rsize` SDP attribute) on `rtcp_rsize`, nonzero NTP timestamps,
//!   zero channel-1 packets on `sr_absent`, and no IP literals in CNAMEs;
//! - one truthful `CAPLOG` record per step via `caplog_support::Record`.

use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use fss_core::ContentDigest;
use fss_core::json_input::{Value, parse as parse_json};
use fss_packet::{PacketLimits, RtpPacket, SequenceClass, SequenceTracker, StreamKey};
use fss_reference::media_fixture::{
    H264FixtureParams, MEDIA_FIXTURE_NOTE, MediaFixtureError, RTSP_TRANSCRIPT_MAGIC_HEADER,
    RtspTranscriptFixture, RtspTranscriptParams, TranscriptDirection, build_rtsp_manifest_json,
    generate_h264_annexb, generate_transcript_auth_required,
    generate_transcript_bad_content_length, generate_transcript_clean,
    generate_transcript_get_parameter_keepalive, generate_transcript_interleave_split,
    generate_transcript_rtcp_rsize, generate_transcript_session_timeout,
    generate_transcript_sr_absent, parse_transcript, verify_fixture_manifest,
};

mod caplog_support;
use caplog_support::Record;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const PINNED_TRANSCRIPTS: [(&str, &str, usize, usize, usize, usize); 8] = [
    (
        "clean.transcript",
        "76466b3c4a20de1026920697eff2c240a0c25d82056e8d85ef9edde905389b07",
        5437,
        28,
        15,
        3,
    ),
    (
        "auth_required.transcript",
        "c2d19f964ccfaa656b89e7c48cd9d7272558a420b7a687ab40a50aa88ed63a0c",
        261,
        2,
        0,
        0,
    ),
    (
        "interleave_split.transcript",
        "3dd594eba7ed5b98cc62ed8b33997dd4cc932be3e698d849cae364b6c683bbf5",
        5446,
        29,
        15,
        3,
    ),
    (
        "bad_content_length.transcript",
        "4ba38d4cf689abe2d505cbed0321d31397eb5b1347ed1106c9cb9a4ede5b1342",
        687,
        4,
        0,
        0,
    ),
    (
        "session_timeout_header.transcript",
        "481aa6ed4c62e7a56cdcff42cb179907c7647bfe6e4118066393e6b2d1b78f1a",
        5437,
        28,
        15,
        3,
    ),
    (
        "rtcp_rsize.transcript",
        "8f268b4232377deaf4f0a84b93200d62d5a67b0bb3076dacad2b2bdef8e0bc11",
        5331,
        28,
        15,
        3,
    ),
    (
        "sr_absent.transcript",
        "8cb42ac5fa03fe84945e5a9fed073400c0b17003cf200cf6396e75a60ef52242",
        5194,
        25,
        15,
        0,
    ),
    (
        "get_parameter_keepalive.transcript",
        "dc8440930c7c94b044c850144743e51a50db95cb87d2b12c00fb9adb6d30b759",
        5586,
        30,
        15,
        3,
    ),
];

fn repo_root() -> TestResult<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .ok_or_else(|| "cannot locate repository root".into())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ContentDigest::sha256(bytes);
    let mut hex = String::with_capacity(64);
    for b in digest.bytes() {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Independent transcript container parser: validates magic header, walks `dir(1) + offset_ms(4)
/// + len(4) + payload(len)`, and returns exact parsed records plus total consumed bytes.
struct RawRecord {
    direction: u8,
    offset_ms: u32,
    payload: Vec<u8>,
}

fn parse_transcript_independently(bytes: &[u8]) -> Result<(Vec<RawRecord>, usize), String> {
    let magic = b"#!fss-rtsp-transcript v1\n";
    if !bytes.starts_with(magic) {
        return Err("missing magic header".to_owned());
    }
    let mut pos = magic.len();
    let mut records = Vec::new();
    while pos < bytes.len() {
        if pos + 9 > bytes.len() {
            return Err(format!("truncated record header at byte {pos}"));
        }
        let direction = bytes[pos];
        if direction > 1 {
            return Err(format!("invalid direction {direction} at byte {pos}"));
        }
        let offset_ms = u32::from_be_bytes([
            bytes[pos + 1],
            bytes[pos + 2],
            bytes[pos + 3],
            bytes[pos + 4],
        ]);
        let len = u32::from_be_bytes([
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
            bytes[pos + 8],
        ]) as usize;
        pos += 9;
        if pos + len > bytes.len() {
            return Err(format!(
                "truncated record payload at byte {pos}: declared {len}, remaining {}",
                bytes.len() - pos
            ));
        }
        records.push(RawRecord {
            direction,
            offset_ms,
            payload: bytes[pos..pos + len].to_vec(),
        });
        pos += len;
    }
    Ok((records, pos))
}

/// Independent Annex-B start-code splitter (strips trailing_zero_8bits before next start code).
fn split_annexb_nals(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut starts: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(&[0, 0, 0, 1]) {
            starts.push((i, 4));
            i += 4;
        } else if bytes[i..].starts_with(&[0, 0, 1]) {
            starts.push((i, 3));
            i += 3;
        } else {
            i += 1;
        }
    }
    starts
        .iter()
        .enumerate()
        .map(|(idx, &(begin, prefix_len))| {
            let start = begin + prefix_len;
            let mut end = starts
                .get(idx + 1)
                .map_or(bytes.len(), |&(next_begin, _)| next_begin);
            while end > start && bytes[end - 1] == 0 {
                end -= 1;
            }
            bytes[start..end].to_vec()
        })
        .collect()
}

/// Independent strict RFC 4648 standard Base64 decoder.
fn decode_base64_independent(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.as_bytes();
    let (chunks, remainder) = bytes.as_chunks::<4>();
    if bytes.is_empty() || !remainder.is_empty() {
        return Err(format!("invalid base64 length {}", bytes.len()));
    }
    let mut out = Vec::with_capacity(chunks.len() * 3);
    for (chunk_idx, chunk) in chunks.iter().enumerate() {
        let is_last = chunk_idx + 1 == chunks.len();
        let decode_val = |b: u8| -> Result<u8, String> {
            match b {
                b'A'..=b'Z' => Ok(b - b'A'),
                b'a'..=b'z' => Ok(b - b'a' + 26),
                b'0'..=b'9' => Ok(b - b'0' + 52),
                b'+' => Ok(62),
                b'/' => Ok(63),
                _ => Err(format!("invalid base64 byte {b:#04x}")),
            }
        };
        let v0 = decode_val(chunk[0])?;
        let v1 = decode_val(chunk[1])?;
        let pad2 = chunk[2] == b'=';
        let pad3 = chunk[3] == b'=';
        if (pad2 || pad3) && !is_last {
            return Err("padding before final quantum".to_owned());
        }
        if pad2 && !pad3 {
            return Err("invalid base64 padding".to_owned());
        }
        out.push((v0 << 2) | (v1 >> 4));
        if !pad2 {
            let v2 = decode_val(chunk[2])?;
            out.push((v1 << 4) | (v2 >> 2));
            if !pad3 {
                let v3 = decode_val(chunk[3])?;
                out.push((v2 << 6) | v3);
            }
        }
    }
    Ok(out)
}

/// Independent detector for ASCII case-insensitive `Authorization:` header token.
fn contains_authorization_header(bytes: &[u8]) -> bool {
    let needle = b"authorization:";
    bytes
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// Independent IPv4 dotted-quad detector (matches `a.b.c.d` where each octet is 0..=255 and not
/// embedded inside a longer alphanumeric/dot identifier token).
fn contains_ipv4_literal(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit()
            && (i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'.'))
        {
            let mut pos = i;
            let mut octets = 0_u8;
            let mut valid = true;
            for part in 0..4 {
                let start = pos;
                while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                    pos += 1;
                }
                let digits = &text[start..pos];
                if digits.is_empty()
                    || digits.len() > 3
                    || digits.parse::<u16>().is_err_and(|_| true)
                {
                    valid = false;
                    break;
                }
                if digits.parse::<u16>().is_ok_and(|n| n > 255) {
                    valid = false;
                    break;
                }
                octets += 1;
                if part < 3 {
                    if pos >= bytes.len() || bytes[pos] != b'.' {
                        valid = false;
                        break;
                    }
                    pos += 1;
                }
            }
            if valid
                && octets == 4
                && (pos == bytes.len()
                    || !(bytes[pos].is_ascii_alphanumeric() || bytes[pos] == b'.'))
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Independent IPv6 literal detector (scans maximal `[0-9a-fA-F:]` tokens bounded by non-identifier
/// characters and parses RFC 4291 full or `::`-compressed forms, ignoring Rust paths like
/// `fss-reference::media_fixture` and ordinary RTSP headers like `a:b`).
fn contains_ipv6_literal(text: &str) -> bool {
    let bytes = text.as_bytes();
    let is_ident_char = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_hexdigit() || bytes[i] == b':' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_hexdigit() || bytes[i] == b':') {
                i += 1;
            }
            let left_ok = start == 0 || !is_ident_char(bytes[start - 1]);
            let right_ok = i == bytes.len() || !is_ident_char(bytes[i]);
            let token = &text[start..i];
            if left_ok && right_ok && is_ipv6_token(token) {
                return true;
            }
        } else {
            i += 1;
        }
    }
    false
}

fn is_ipv6_token(token: &str) -> bool {
    if token.matches(':').count() < 2 {
        return false;
    }
    if token.contains(":::") {
        return false;
    }
    let double_colons = token.matches("::").count();
    if double_colons > 1 {
        return false;
    }
    let valid_group =
        |g: &str| !g.is_empty() && g.len() <= 4 && g.bytes().all(|b| b.is_ascii_hexdigit());
    if double_colons == 1 {
        let mut parts = token.splitn(2, "::");
        let left = parts.next().unwrap_or("");
        let right = parts.next().unwrap_or("");
        let left_groups: Vec<&str> = if left.is_empty() {
            Vec::new()
        } else {
            left.split(':').collect()
        };
        let right_groups: Vec<&str> = if right.is_empty() {
            Vec::new()
        } else {
            right.split(':').collect()
        };
        if !left_groups.iter().all(|g| valid_group(g))
            || !right_groups.iter().all(|g| valid_group(g))
        {
            return false;
        }
        left_groups.len() + right_groups.len() <= 7
    } else {
        let groups: Vec<&str> = token.split(':').collect();
        groups.len() == 8 && groups.iter().all(|g| valid_group(g))
    }
}

/// Independent RTSP + interleaved-TCP (`$`) demuxer over S2C records.
/// Concatenates consecutive S2C records into one stream so `interleave_split` reassembles cleanly.
struct DemuxedS2c {
    rtsp_messages: Vec<String>,
    interleaved: Vec<(u8, Vec<u8>)>,
}

fn demux_s2c_stream(records: &[RawRecord]) -> Result<DemuxedS2c, String> {
    let mut stream = Vec::new();
    for rec in records {
        if rec.direction == 1 {
            stream.extend_from_slice(&rec.payload);
        }
    }
    let mut pos = 0;
    let mut rtsp_messages = Vec::new();
    let mut interleaved = Vec::new();
    while pos < stream.len() {
        if stream[pos] == b'$' {
            if pos + 4 > stream.len() {
                return Err(format!("truncated interleaved frame header at {pos}"));
            }
            let channel = stream[pos + 1];
            let len = u16::from_be_bytes([stream[pos + 2], stream[pos + 3]]) as usize;
            pos += 4;
            if pos + len > stream.len() {
                return Err(format!("truncated interleaved payload at {pos}"));
            }
            interleaved.push((channel, stream[pos..pos + len].to_vec()));
            pos += len;
        } else if stream[pos..].starts_with(b"RTSP/1.0 ") {
            let header_end = stream[pos..]
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .ok_or_else(|| format!("unterminated RTSP header at {pos}"))?;
            let header_bytes = &stream[pos..pos + header_end];
            let header_text = String::from_utf8(header_bytes.to_vec())
                .map_err(|e| format!("non-utf8 RTSP header: {e}"))?;
            let mut body_len = 0_usize;
            for line in header_text.split("\r\n").skip(1) {
                if let Some((name, val)) = line.split_once(':')
                    && name.trim().eq_ignore_ascii_case("content-length")
                {
                    if let Ok(parsed) = val.trim().parse::<usize>() {
                        body_len = parsed;
                    } else {
                        // Deliberately malformed Content-Length (e.g. bad_content_length fixture):
                        // consume remaining bytes in this single response.
                        body_len = stream.len() - (pos + header_end + 4);
                    }
                }
            }
            let msg_end = pos + header_end + 4 + body_len;
            if msg_end > stream.len() {
                return Err(format!("truncated RTSP body at {pos}"));
            }
            let full_text = String::from_utf8(stream[pos..msg_end].to_vec())
                .map_err(|e| format!("non-utf8 RTSP message: {e}"))?;
            rtsp_messages.push(full_text);
            pos = msg_end;
        } else {
            return Err(format!(
                "unexpected S2C framing byte {:#04x} at offset {pos}",
                stream[pos]
            ));
        }
    }
    Ok(DemuxedS2c {
        rtsp_messages,
        interleaved,
    })
}

/// Independent RFC 3550 RTCP compound / reduced-size packet walker (without using `fss-packet`).
#[derive(Debug, Eq, PartialEq)]
struct WalkedRtcp {
    packet_types: Vec<u8>,
    sr_ssrc: u32,
    ntp_seconds: u32,
    ntp_fraction: u32,
    rtp_timestamp: u32,
    packet_count: u32,
    octet_count: u32,
    sdes_cname: Option<(u32, String)>,
}

fn walk_rtcp_payload(payload: &[u8]) -> Result<WalkedRtcp, String> {
    if payload.len() < 28 || !payload.len().is_multiple_of(4) {
        return Err(format!("invalid RTCP payload length {}", payload.len()));
    }
    let mut pos = 0;
    let mut packet_types = Vec::new();
    let mut sr_fields: Option<(u32, u32, u32, u32, u32, u32)> = None;
    let mut sdes_cname: Option<(u32, String)> = None;

    while pos < payload.len() {
        if pos + 4 > payload.len() {
            return Err(format!("truncated RTCP common header at {pos}"));
        }
        let b0 = payload[pos];
        let version = b0 >> 6;
        let count = b0 & 0x1f;
        let pt = payload[pos + 1];
        let word_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        let byte_len = (word_len + 1) * 4;
        if version != 2 {
            return Err(format!("RTCP version {version} != 2 at {pos}"));
        }
        if pos + byte_len > payload.len() {
            return Err(format!(
                "RTCP packet at {pos} declares {byte_len} bytes, only {} remain",
                payload.len() - pos
            ));
        }
        let pkt = &payload[pos..pos + byte_len];
        packet_types.push(pt);

        if packet_types.len() == 1 {
            if pt != 200 {
                return Err(format!(
                    "first RTCP packet must be SR (PT 200), got PT {pt}"
                ));
            }
            if byte_len < 28 {
                return Err(format!("RTCP SR too short: {byte_len} bytes"));
            }
            let ssrc = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
            let ntp_sec = u32::from_be_bytes([pkt[8], pkt[9], pkt[10], pkt[11]]);
            let ntp_frac = u32::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]);
            let rtp_ts = u32::from_be_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
            let pkt_cnt = u32::from_be_bytes([pkt[20], pkt[21], pkt[22], pkt[23]]);
            let oct_cnt = u32::from_be_bytes([pkt[24], pkt[25], pkt[26], pkt[27]]);
            if ntp_sec == 0 && ntp_frac == 0 {
                return Err("RTCP SR has zero NTP timestamp".to_owned());
            }
            sr_fields = Some((ssrc, ntp_sec, ntp_frac, rtp_ts, pkt_cnt, oct_cnt));
        } else if pt == 202 {
            if count == 0 {
                return Err("RTCP SDES has 0 chunks".to_owned());
            }
            let mut sdes_pos = 4;
            for _ in 0..count {
                if sdes_pos + 4 > pkt.len() {
                    return Err("truncated SDES chunk SSRC".to_owned());
                }
                let chunk_ssrc = u32::from_be_bytes([
                    pkt[sdes_pos],
                    pkt[sdes_pos + 1],
                    pkt[sdes_pos + 2],
                    pkt[sdes_pos + 3],
                ]);
                sdes_pos += 4;
                let mut terminated = false;
                while sdes_pos < pkt.len() {
                    let item_type = pkt[sdes_pos];
                    sdes_pos += 1;
                    if item_type == 0 {
                        terminated = true;
                        while !sdes_pos.is_multiple_of(4) && sdes_pos < pkt.len() {
                            if pkt[sdes_pos] != 0 {
                                return Err("non-zero SDES padding byte".to_owned());
                            }
                            sdes_pos += 1;
                        }
                        break;
                    }
                    if sdes_pos >= pkt.len() {
                        return Err("truncated SDES item length".to_owned());
                    }
                    let item_len = pkt[sdes_pos] as usize;
                    sdes_pos += 1;
                    if sdes_pos + item_len > pkt.len() {
                        return Err("truncated SDES item payload".to_owned());
                    }
                    if item_type == 1 {
                        let cname = String::from_utf8(pkt[sdes_pos..sdes_pos + item_len].to_vec())
                            .map_err(|e| format!("non-utf8 CNAME: {e}"))?;
                        sdes_cname = Some((chunk_ssrc, cname));
                    }
                    sdes_pos += item_len;
                }
                if !terminated {
                    return Err("unterminated SDES chunk".to_owned());
                }
            }
        }

        pos += byte_len;
    }

    let (sr_ssrc, ntp_seconds, ntp_fraction, rtp_timestamp, packet_count, octet_count) =
        sr_fields.ok_or_else(|| "missing RTCP SR".to_owned())?;
    Ok(WalkedRtcp {
        packet_types,
        sr_ssrc,
        ntp_seconds,
        ntp_fraction,
        rtp_timestamp,
        packet_count,
        octet_count,
        sdes_cname,
    })
}

fn generate_all_rtsp_fixtures() -> TestResult<(RtspTranscriptParams, Vec<RtspTranscriptFixture>)> {
    let annexb = generate_h264_annexb(&H264FixtureParams::default())?;
    let params = RtspTranscriptParams::default();
    let fixtures = vec![
        generate_transcript_clean(&annexb, &params)?,
        generate_transcript_auth_required(&params)?,
        generate_transcript_interleave_split(&annexb, &params)?,
        generate_transcript_bad_content_length(&annexb, &params)?,
        generate_transcript_session_timeout(&annexb, &params)?,
        generate_transcript_rtcp_rsize(&annexb, &params)?,
        generate_transcript_sr_absent(&annexb, &params)?,
        generate_transcript_get_parameter_keepalive(&annexb, &params)?,
    ];
    Ok((params, fixtures))
}

fn sequence_class_name(class: SequenceClass) -> &'static str {
    match class {
        SequenceClass::Probation => "Probation",
        SequenceClass::Baseline => "Baseline",
        SequenceClass::Advanced => "Advanced",
        SequenceClass::Reordered => "Reordered",
        SequenceClass::Duplicate => "Duplicate",
        SequenceClass::BeforeBaseline => "BeforeBaseline",
        SequenceClass::DiscontinuitySuspected => "DiscontinuitySuspected",
        SequenceClass::RestartRequired => "RestartRequired",
    }
}

#[test]
fn regeneration_and_manifest_are_byte_identical_to_committed_fixtures() -> TestResult {
    let root = repo_root()?;
    let rtsp_dir = root.join("tests/fixtures/media/rtsp");
    let (params, regenerated) = generate_all_rtsp_fixtures()?;
    assert_eq!(regenerated.len(), PINNED_TRANSCRIPTS.len());

    let manifest_disk = fs::read_to_string(rtsp_dir.join("fixture_manifest.json"))?;
    let manifest_regen = build_rtsp_manifest_json(&regenerated, &params);
    assert_eq!(
        manifest_disk, manifest_regen,
        "committed RTSP fixture_manifest.json drifted from generator"
    );
    assert!(manifest_disk.contains(MEDIA_FIXTURE_NOTE));

    for (fixture, &(name, pinned_sha, pinned_len, pinned_recs, pinned_rtp, pinned_rtcp)) in
        regenerated.iter().zip(&PINNED_TRANSCRIPTS)
    {
        assert_eq!(fixture.filename, name);
        let disk_bytes = fs::read(rtsp_dir.join(name))?;
        let disk_sha = sha256_hex(&disk_bytes);
        verify_fixture_manifest(&manifest_disk, name, &disk_bytes)?;

        // Tamper detection: flipping one byte must fail manifest verification with DigestMismatch.
        let mut tampered = disk_bytes.clone();
        tampered[RTSP_TRANSCRIPT_MAGIC_HEADER.len()] ^= 0x01;
        let tamper_rejected = matches!(
            verify_fixture_manifest(&manifest_disk, name, &tampered),
            Err(MediaFixtureError::DigestMismatch { .. })
        );

        let rec = Record::new(&format!("rtsp_regen_{}", fixture.variant_name))
            .check("sha256", pinned_sha, disk_sha.as_str())
            .check("byte_len", pinned_len, disk_bytes.len())
            .check("regen_matches_disk", true, disk_bytes == fixture.bytes)
            .check("record_count", pinned_recs, fixture.records.len())
            .check("rtp_packet_count", pinned_rtp, fixture.packets.len())
            .check(
                "rtcp_report_count",
                pinned_rtcp,
                fixture.sender_reports.len(),
            )
            .check("tamper_rejected", true, tamper_rejected);
        rec.emit_checked(0, rec.passed());
        assert!(rec.passed(), "regeneration mismatch for {name}");
    }

    Ok(())
}

#[test]
fn independent_record_framing_and_c2s_cseq_hold_for_every_fixture() -> TestResult {
    let root = repo_root()?;
    let rtsp_dir = root.join("tests/fixtures/media/rtsp");
    let manifest = parse_json(&fs::read_to_string(rtsp_dir.join("fixture_manifest.json"))?)?;
    let entries = manifest.object().ok_or("manifest object")?["fixtures"]
        .array()
        .ok_or("fixtures array")?;
    assert_eq!(entries.len(), PINNED_TRANSCRIPTS.len());

    for &(name, _, expected_len, expected_records, _, _) in &PINNED_TRANSCRIPTS {
        let bytes = fs::read(rtsp_dir.join(name))?;
        let (raw_records, consumed) =
            parse_transcript_independently(&bytes).map_err(|e| format!("{name}: {e}"))?;
        let api_records = parse_transcript(&bytes)?;

        let sum_len = RTSP_TRANSCRIPT_MAGIC_HEADER.len()
            + raw_records
                .iter()
                .map(|r| 9 + r.payload.len())
                .sum::<usize>();
        let mut c2s_count = 0_usize;
        let mut c2s_with_cseq = 0_usize;
        let mut saw_get_parameter = false;
        let mut saw_teardown_cseq6 = false;
        let mut prev_offset = 0_u32;
        let mut monotonic_offsets = true;

        for (raw, api) in raw_records.iter().zip(&api_records) {
            if raw.offset_ms < prev_offset {
                monotonic_offsets = false;
            }
            prev_offset = raw.offset_ms;
            assert_eq!(raw.direction, api.direction.as_u8(), "{name}");
            assert_eq!(raw.offset_ms, api.offset_ms, "{name}");
            assert_eq!(raw.payload, api.bytes, "{name}");
            if raw.direction == TranscriptDirection::ClientToServer.as_u8() {
                c2s_count += 1;
                let text = std::str::from_utf8(&raw.payload)?;
                let has_cseq = text.split("\r\n").skip(1).any(|line| {
                    line.split_once(':').is_some_and(|(k, v)| {
                        k.trim().eq_ignore_ascii_case("cseq") && v.trim().parse::<u32>().is_ok()
                    })
                });
                if has_cseq {
                    c2s_with_cseq += 1;
                }
                if text.starts_with("GET_PARAMETER ") && text.contains("CSeq: 5\r\n") {
                    saw_get_parameter = true;
                }
                if text.starts_with("TEARDOWN ") && text.contains("CSeq: 6\r\n") {
                    saw_teardown_cseq6 = true;
                }
            }
        }

        let variant = name.trim_end_matches(".transcript");
        let keepalive_ok = if variant == "get_parameter_keepalive" {
            saw_get_parameter && saw_teardown_cseq6
        } else {
            !saw_get_parameter
        };
        let rec = Record::new(&format!("rtsp_framing_{variant}"))
            .check("consumed_eq_file_len", bytes.len(), consumed)
            .check("sum_eq_expected_len", expected_len, sum_len)
            .check("record_count", expected_records, raw_records.len())
            .check("api_record_count", raw_records.len(), api_records.len())
            .check("c2s_nonzero", true, c2s_count > 0)
            .check("every_c2s_has_cseq", c2s_count, c2s_with_cseq)
            .check("monotonic_offsets", true, monotonic_offsets)
            .check("keepalive_variant_shape", true, keepalive_ok);
        rec.emit_checked(0, rec.passed());
        assert!(rec.passed(), "framing check failed for {name}");
    }

    Ok(())
}

#[test]
fn zero_credentials_and_zero_ip_literals_guard_with_negative_controls() -> TestResult {
    // Negative controls proving our scanners detect credentials, IPv4, and IPv6 literals.
    assert!(contains_authorization_header(
        b"DESCRIBE rtsp://x RTSP/1.0\r\nAuthorization: Basic dXNlcjpwYXNz\r\n"
    ));
    assert!(contains_authorization_header(
        b"authorization: Digest username=\"admin\""
    ));
    assert!(!contains_authorization_header(
        b"WWW-Authenticate: Digest realm=\"fixture.invalid\""
    ));

    for ipv4 in [
        "192.168.1.10",
        "10.0.0.1",
        "127.0.0.1",
        "rtsp://198.51.100.7/live",
    ] {
        assert!(contains_ipv4_literal(ipv4), "IPv4 scanner missed {ipv4}");
    }
    for non_ipv4 in ["rtsp://fixture.invalid/stream", "v=0", "1.0.0", "999.1.1.1"] {
        assert!(
            !contains_ipv4_literal(non_ipv4),
            "IPv4 scanner false-positive on {non_ipv4}"
        );
    }

    for ipv6 in [
        "2001:db8::1",
        "::1",
        "fe80::1ff:fe23:4567:890a",
        "rtsp://[2001:0db8:0000:0000:0000:0000:0000:0001]/s",
    ] {
        assert!(contains_ipv6_literal(ipv6), "IPv6 scanner missed {ipv6}");
    }
    for non_ipv6 in [
        "rtsp://fixture.invalid/stream",
        "a=rtpmap:96 H264/90000",
        "Session: 12345678;timeout=60",
        "fss-fixture@fixture.invalid",
        "fss-reference::media_fixture::rtsp",
    ] {
        assert!(
            !contains_ipv6_literal(non_ipv6),
            "IPv6 scanner false-positive on {non_ipv6}"
        );
    }

    let root = repo_root()?;
    let rtsp_dir = root.join("tests/fixtures/media/rtsp");
    for &(name, ..) in &PINNED_TRANSCRIPTS {
        let bytes = fs::read(rtsp_dir.join(name))?;
        let (records, _) = parse_transcript_independently(&bytes)?;
        let mut auth_hits = 0_usize;
        let mut ipv4_hits = 0_usize;
        let mut ipv6_hits = 0_usize;
        for rec in &records {
            if contains_authorization_header(&rec.payload) {
                auth_hits += 1;
            }
            // Scan text messages and printable ASCII runs across every record payload.
            if let Ok(text) = std::str::from_utf8(&rec.payload) {
                if contains_ipv4_literal(text) {
                    ipv4_hits += 1;
                }
                if contains_ipv6_literal(text) {
                    ipv6_hits += 1;
                }
            }
        }
        // Also scan the manifest entry text itself (no IP literals or Authorization headers).
        let variant = name.trim_end_matches(".transcript");
        let rec = Record::new(&format!("rtsp_security_{variant}"))
            .check("authorization_headers", 0_usize, auth_hits)
            .check("ipv4_literals", 0_usize, ipv4_hits)
            .check("ipv6_literals", 0_usize, ipv6_hits);
        rec.emit_checked(0, rec.passed());
        assert!(rec.passed(), "security guard tripped on {name}");
    }

    let manifest_text = fs::read_to_string(rtsp_dir.join("fixture_manifest.json"))?;
    let manifest_rec = Record::new("rtsp_security_manifest")
        .check(
            "authorization_headers",
            false,
            contains_authorization_header(manifest_text.as_bytes()),
        )
        .check(
            "ipv4_literals",
            false,
            contains_ipv4_literal(&manifest_text),
        )
        .check(
            "ipv6_literals",
            false,
            contains_ipv6_literal(&manifest_text),
        );
    manifest_rec.emit_checked(0, manifest_rec.passed());
    assert!(manifest_rec.passed());

    Ok(())
}

#[test]
fn sdp_base64_sps_pps_matches_fixh264_and_rtcp_rsize_attribute() -> TestResult {
    let root = repo_root()?;
    let h264_bytes = fs::read(root.join("tests/fixtures/media/h264/clean.264"))?;
    let nals = split_annexb_nals(&h264_bytes);
    let expected_sps = nals
        .iter()
        .find(|n| !n.is_empty() && (n[0] & 0x1f) == 7)
        .ok_or("clean.264 missing SPS NAL (type 7)")?;
    let expected_pps = nals
        .iter()
        .find(|n| !n.is_empty() && (n[0] & 0x1f) == 8)
        .ok_or("clean.264 missing PPS NAL (type 8)")?;

    let rtsp_dir = root.join("tests/fixtures/media/rtsp");
    for &(name, ..) in &PINNED_TRANSCRIPTS {
        if name == "auth_required.transcript" {
            continue;
        }
        let bytes = fs::read(rtsp_dir.join(name))?;
        let (records, _) = parse_transcript_independently(&bytes)?;
        let demuxed = demux_s2c_stream(&records)?;
        let describe_resp = demuxed
            .rtsp_messages
            .iter()
            .find(|m| m.contains("Content-Type: application/sdp"))
            .ok_or_else(|| format!("{name}: missing DESCRIBE SDP response"))?;
        let (_, sdp) = describe_resp
            .split_once("\r\n\r\n")
            .ok_or_else(|| format!("{name}: missing SDP body separator"))?;
        let sprop = sdp
            .split("\r\n")
            .find_map(|line| {
                line.split_once("sprop-parameter-sets=")
                    .map(|(_, rest)| rest)
            })
            .ok_or_else(|| format!("{name}: missing sprop-parameter-sets"))?;
        let (sps_b64, pps_b64) = sprop
            .split_once(',')
            .ok_or_else(|| format!("{name}: malformed sprop-parameter-sets {sprop}"))?;
        let decoded_sps = decode_base64_independent(sps_b64.trim())?;
        let decoded_pps = decode_base64_independent(pps_b64.trim())?;
        let has_rtcp_rsize = sdp.split("\r\n").any(|line| line == "a=rtcp-rsize");
        let expect_rsize = name == "rtcp_rsize.transcript";
        let variant = name.trim_end_matches(".transcript");

        let rec = Record::new(&format!("rtsp_sdp_{variant}"))
            .check(
                "sps_matches_fixh264",
                expected_sps.as_slice(),
                decoded_sps.as_slice(),
            )
            .check(
                "pps_matches_fixh264",
                expected_pps.as_slice(),
                decoded_pps.as_slice(),
            )
            .check("has_rtcp_rsize_attr", expect_rsize, has_rtcp_rsize);
        rec.emit_checked(0, rec.passed());
        assert!(rec.passed(), "SDP check failed for {name}");
    }
    Ok(())
}

#[test]
fn per_packet_sequence_classes_and_independent_rtcp_walker_match_contract() -> TestResult {
    // Negative controls on the independent RTCP walker.
    assert!(
        walk_rtcp_payload(&[0x80, 200, 0, 6]).is_err(),
        "truncated SR must fail"
    );
    let mut zero_ntp = vec![0_u8; 28];
    zero_ntp[0] = 0x80;
    zero_ntp[1] = 200;
    zero_ntp[3] = 6;
    assert!(
        walk_rtcp_payload(&zero_ntp).is_err(),
        "zero NTP SR must fail"
    );

    let root = repo_root()?;
    let rtsp_dir = root.join("tests/fixtures/media/rtsp");
    let manifest = parse_json(&fs::read_to_string(rtsp_dir.join("fixture_manifest.json"))?)?;
    let manifest_fixtures = manifest.object().ok_or("manifest")?["fixtures"]
        .array()
        .ok_or("fixtures")?;

    let params = RtspTranscriptParams::default();
    let expected_classes: Vec<&str> = std::iter::once("Probation")
        .chain(std::iter::once("Baseline"))
        .chain(std::iter::repeat_n("Advanced", 13))
        .collect();

    for &(name, _, _, _, expected_rtp_count, expected_rtcp_count) in &PINNED_TRANSCRIPTS {
        let bytes = fs::read(rtsp_dir.join(name))?;
        let (records, _) = parse_transcript_independently(&bytes)?;
        let demuxed = demux_s2c_stream(&records)?;

        let rtp_payloads: Vec<&[u8]> = demuxed
            .interleaved
            .iter()
            .filter(|(ch, _)| *ch == 0)
            .map(|(_, p)| p.as_slice())
            .collect();
        let rtcp_payloads: Vec<&[u8]> = demuxed
            .interleaved
            .iter()
            .filter(|(ch, _)| *ch == 1)
            .map(|(_, p)| p.as_slice())
            .collect();

        let manifest_entry = manifest_fixtures
            .iter()
            .find_map(|v| {
                let obj = v.object()?;
                (obj.get("name")?.text()? == name).then_some(obj)
            })
            .ok_or_else(|| format!("missing manifest entry for {name}"))?;

        let manifest_classes: Vec<String> = manifest_entry["expected_packets"]
            .array()
            .ok_or("expected_packets")?
            .iter()
            .map(|p| {
                p.object()
                    .and_then(|o| o.get("expected_sequence_class"))
                    .and_then(Value::text)
                    .map(str::to_owned)
                    .ok_or("expected_sequence_class")
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Feed every channel-0 RTP packet through fss_packet::RtpPacket::parse + SequenceTracker.
        let key = StreamKey {
            ingress: 1,
            generation: 1,
            ssrc: params.ssrc,
        };
        let mut tracker =
            SequenceTracker::new(key, params.payload_type).map_err(|e| format!("{e}"))?;
        let mut observed_classes = Vec::with_capacity(rtp_payloads.len());
        for raw_rtp in &rtp_payloads {
            let pkt = RtpPacket::parse(raw_rtp, PacketLimits::default())?;
            let obs = tracker.observe(key, pkt).map_err(|e| format!("{e}"))?;
            observed_classes.push(sequence_class_name(obs.class).to_owned());
        }

        let target_classes: Vec<String> = if expected_rtp_count == 0 {
            Vec::new()
        } else {
            expected_classes.iter().map(|s| (*s).to_owned()).collect()
        };

        // Independently walk every channel-1 RTCP payload.
        let is_rsize = name == "rtcp_rsize.transcript";
        let manifest_srs = manifest_entry["sender_reports"]
            .array()
            .ok_or("sender_reports")?;
        let mut all_rtcp_valid =
            rtcp_payloads.len() == expected_rtcp_count && manifest_srs.len() == expected_rtcp_count;
        let mut all_ntp_nonzero = true;
        let mut compound_match = true;
        let mut cname_clean = true;

        for (raw_rtcp, man_sr) in rtcp_payloads.iter().zip(manifest_srs) {
            let walked = walk_rtcp_payload(raw_rtcp).map_err(|e| format!("{name}: {e}"))?;
            let sr_obj = man_sr.object().ok_or("sr object")?;
            let man_ntp_sec = sr_obj["ntp_seconds"].integer().ok_or("ntp_seconds")? as u32;
            let man_ntp_frac = sr_obj["ntp_fraction"].integer().ok_or("ntp_fraction")? as u32;
            let man_rtp_ts = sr_obj["rtp_timestamp"].integer().ok_or("rtp_timestamp")? as u32;
            let man_pkt_cnt = sr_obj["packet_count"].integer().ok_or("packet_count")? as u32;
            let man_oct_cnt = sr_obj["octet_count"].integer().ok_or("octet_count")? as u32;
            all_ntp_nonzero &= walked.ntp_seconds != 0 || walked.ntp_fraction != 0;
            all_rtcp_valid &= walked.sr_ssrc == params.ssrc
                && walked.ntp_seconds == man_ntp_sec
                && walked.ntp_fraction == man_ntp_frac
                && walked.rtp_timestamp == man_rtp_ts
                && walked.packet_count == man_pkt_cnt
                && walked.octet_count == man_oct_cnt;

            if is_rsize {
                compound_match &= walked.packet_types == vec![200]
                    && raw_rtcp.len() == 28
                    && walked.sdes_cname.is_none();
            } else {
                let sdes_ok = match &walked.sdes_cname {
                    Some((ssrc, cname)) => {
                        let no_ip = !contains_ipv4_literal(cname) && !contains_ipv6_literal(cname);
                        cname_clean &= no_ip;
                        *ssrc == params.ssrc && cname == params.cname
                    }
                    None => false,
                };
                compound_match &= walked.packet_types == vec![200, 202] && sdes_ok;
            }
        }

        let variant = name.trim_end_matches(".transcript");
        let rec = Record::new(&format!("rtsp_media_rtcp_{variant}"))
            .check("rtp_count", expected_rtp_count, rtp_payloads.len())
            .check("rtcp_count", expected_rtcp_count, rtcp_payloads.len())
            .check("sequence_classes", target_classes.clone(), observed_classes)
            .check(
                "manifest_sequence_classes",
                target_classes,
                manifest_classes,
            )
            .check("rtcp_fields_valid", true, all_rtcp_valid)
            .check("rtcp_ntp_nonzero", true, all_ntp_nonzero)
            .check("rtcp_compound_or_rsize_exact", true, compound_match)
            .check("rtcp_cname_no_ip", true, cname_clean);
        rec.emit_checked(0, rec.passed());
        assert!(rec.passed(), "RTP/RTCP verification failed for {name}");
    }

    Ok(())
}

#![forbid(unsafe_code)]
//! Integration contract tests for the bounded MJPEG/JPEG frame splitter (fss-2h5zq.22).
//!
//! Companion test suite asserting:
//! - Manifest equality across all MJPEG fixture variants (with on-disk and synthetic streams).
//! - Structured CAPLOG logging per fixture and test group conforming to the E2E harness format.
//! - Hand-built edge cases: FF00 stuffing inside ECS, RSTn restart markers, APPn/COM containing
//!   embedded FFD9, zero-length segments, SOF with 0 components, and fill-byte runs.
//! - Malformed gauntlet: inter-frame garbage, trailing garbage, in-frame garbage, stray stuffing,
//!   short segments, zero height, DNL marker, cut headers, and next-SOI resync.
//! - 10,000-mutation deterministic no-panic gauntlet driven by DeterministicFaultPrng.
//! - Precise limits boundaries: input size, frame size, dimensions, frames count, segment counts.
//! - Cooperative cancellation via ReplayCx.

use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use fss_core::ContentDigest;
use fss_reference::ingest::mjpeg::{
    JpegFinding, JpegSplitError, MjpegLimits, OmissionReason, OmissionSpan, split_jpeg_stream,
};
use fss_reference::{DeterministicFaultPrng, ReplayCx};

/// Emits a single-line structured CAPLOG record for digestion by the E2E logging harness.
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

/// Compute SHA-256 lower-case hex string using fss_core::ContentDigest.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ContentDigest::sha256(bytes);
    let mut hex = String::with_capacity(64);
    for b in digest.bytes() {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

// ---------------------------------------------------------------------------
// Pure-Rust minimal JSON parser for fixture manifest validation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum JsonVal {
    Null,
    Bool(bool),
    Number(i64),
    String(String),
    Array(Vec<JsonVal>),
    Object(Vec<(String, JsonVal)>),
}

impl JsonVal {
    fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Number(n) => Some(*n),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&[JsonVal]> {
        match self {
            Self::Array(arr) => Some(arr.as_slice()),
            _ => None,
        }
    }

    fn get(&self, key: &str) -> Option<&JsonVal> {
        match self {
            Self::Object(entries) => {
                for (k, v) in entries {
                    if k == key {
                        return Some(v);
                    }
                }
                None
            }
            _ => None,
        }
    }
}

struct JsonParser<'a> {
    chars: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn new(chars: &'a [u8]) -> Self {
        Self { chars, pos: 0 }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.chars.len()
            && matches!(self.chars[self.pos], b' ' | b'\t' | b'\r' | b'\n')
        {
            self.pos += 1;
        }
    }

    fn parse_val(&mut self) -> Result<JsonVal, Box<dyn Error>> {
        self.skip_ws();
        if self.pos >= self.chars.len() {
            return Err("unexpected EOF in json".into());
        }
        match self.chars[self.pos] {
            b'n' => {
                if self.chars[self.pos..].starts_with(b"null") {
                    self.pos += 4;
                    Ok(JsonVal::Null)
                } else {
                    Err("expected null".into())
                }
            }
            b't' => {
                if self.chars[self.pos..].starts_with(b"true") {
                    self.pos += 4;
                    Ok(JsonVal::Bool(true))
                } else {
                    Err("expected true".into())
                }
            }
            b'f' => {
                if self.chars[self.pos..].starts_with(b"false") {
                    self.pos += 5;
                    Ok(JsonVal::Bool(false))
                } else {
                    Err("expected false".into())
                }
            }
            b'"' => self.parse_str().map(JsonVal::String),
            b'[' => self.parse_arr(),
            b'{' => self.parse_obj(),
            b'-' | b'0'..=b'9' => self.parse_num(),
            other => Err(format!("unexpected char in json: {}", other as char).into()),
        }
    }

    fn parse_str(&mut self) -> Result<String, Box<dyn Error>> {
        self.pos += 1; // skip opening quote
        let mut s = String::new();
        while self.pos < self.chars.len() {
            let b = self.chars[self.pos];
            self.pos += 1;
            if b == b'"' {
                return Ok(s);
            }
            if b == b'\\' {
                if self.pos >= self.chars.len() {
                    return Err("unexpected EOF after escape".into());
                }
                let esc = self.chars[self.pos];
                self.pos += 1;
                match esc {
                    b'"' => s.push('"'),
                    b'\\' => s.push('\\'),
                    b'/' => s.push('/'),
                    b'b' => s.push('\x08'),
                    b'f' => s.push('\x0c'),
                    b'n' => s.push('\n'),
                    b'r' => s.push('\r'),
                    b't' => s.push('\t'),
                    _ => s.push(esc as char),
                }
            } else {
                s.push(b as char);
            }
        }
        Err("unterminated string".into())
    }

    fn parse_num(&mut self) -> Result<JsonVal, Box<dyn Error>> {
        let start = self.pos;
        if self.pos < self.chars.len() && self.chars[self.pos] == b'-' {
            self.pos += 1;
        }
        while self.pos < self.chars.len() && self.chars[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        let s = std::str::from_utf8(&self.chars[start..self.pos])?;
        let n: i64 = s.parse()?;
        Ok(JsonVal::Number(n))
    }

    fn parse_arr(&mut self) -> Result<JsonVal, Box<dyn Error>> {
        self.pos += 1; // skip [
        let mut arr = Vec::new();
        loop {
            self.skip_ws();
            if self.pos < self.chars.len() && self.chars[self.pos] == b']' {
                self.pos += 1;
                return Ok(JsonVal::Array(arr));
            }
            let item = self.parse_val()?;
            arr.push(item);
            self.skip_ws();
            if self.pos < self.chars.len() && self.chars[self.pos] == b',' {
                self.pos += 1;
            } else if self.pos < self.chars.len() && self.chars[self.pos] == b']' {
                self.pos += 1;
                return Ok(JsonVal::Array(arr));
            } else {
                return Err("expected , or ] in array".into());
            }
        }
    }

    fn parse_obj(&mut self) -> Result<JsonVal, Box<dyn Error>> {
        self.pos += 1; // skip {
        let mut fields = Vec::new();
        loop {
            self.skip_ws();
            if self.pos < self.chars.len() && self.chars[self.pos] == b'}' {
                self.pos += 1;
                return Ok(JsonVal::Object(fields));
            }
            if self.pos >= self.chars.len() || self.chars[self.pos] != b'"' {
                return Err("expected string key in object".into());
            }
            let key = self.parse_str()?;
            self.skip_ws();
            if self.pos >= self.chars.len() || self.chars[self.pos] != b':' {
                return Err("expected : after object key".into());
            }
            self.pos += 1; // skip :
            let val = self.parse_val()?;
            fields.push((key, val));
            self.skip_ws();
            if self.pos < self.chars.len() && self.chars[self.pos] == b',' {
                self.pos += 1;
            } else if self.pos < self.chars.len() && self.chars[self.pos] == b'}' {
                self.pos += 1;
                return Ok(JsonVal::Object(fields));
            } else {
                return Err("expected , or } in object".into());
            }
        }
    }
}

fn parse_json(input: &[u8]) -> Result<JsonVal, Box<dyn Error>> {
    let mut parser = JsonParser::new(input);
    parser.parse_val()
}

// ---------------------------------------------------------------------------
// Helpers for building valid test JPEG structures
// ---------------------------------------------------------------------------

fn helper_sof0(w: u16, h: u16) -> Vec<u8> {
    let mut v = vec![0xFF, 0xC0, 0x00, 0x0B, 0x08];
    v.extend_from_slice(&h.to_be_bytes());
    v.extend_from_slice(&w.to_be_bytes());
    v.extend_from_slice(&[0x01, 0x01, 0x11, 0x00]);
    v
}

fn helper_sos1() -> Vec<u8> {
    vec![0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]
}

fn helper_frame(w: u16, h: u16, ecs: &[u8]) -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8];
    v.extend(helper_sof0(w, h));
    v.extend(helper_sos1());
    v.extend_from_slice(ecs);
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}

fn build_test_jpeg(width: u16, height: u16, payload_byte: u8) -> Vec<u8> {
    let mut data = Vec::with_capacity(128);
    // SOI
    data.extend_from_slice(&[0xFF, 0xD8]);

    // DQT (length = 67, 1 table of 64 bytes)
    data.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00]);
    data.extend_from_slice(&[16u8; 64]);

    // SOF0 (Baseline, 8-bit precision, 3 components)
    data.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
    data.extend_from_slice(&height.to_be_bytes());
    data.extend_from_slice(&width.to_be_bytes());
    data.push(3); // 3 components (Y, Cb, Cr)
    data.extend_from_slice(&[1, 0x11, 0]); // Y: ID 1, 1:1 sampling, QT 0
    data.extend_from_slice(&[2, 0x11, 0]); // Cb: ID 2, 1:1 sampling, QT 0
    data.extend_from_slice(&[3, 0x11, 0]); // Cr: ID 3, 1:1 sampling, QT 0

    // SOS (Start of Scan)
    data.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x0C, 0x03]);
    data.extend_from_slice(&[1, 0x00, 2, 0x11, 3, 0x11, 0x00, 0x3F, 0x00]);

    // Entropy-coded segment (ECS)
    data.extend_from_slice(&[payload_byte, 0x42, 0x99]);

    // EOI
    data.extend_from_slice(&[0xFF, 0xD9]);
    data
}

// ---------------------------------------------------------------------------
// Step 1: Cooperative cancellation checkpoints
// ---------------------------------------------------------------------------

#[test]
fn test_cancellation_checkpoints() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let frame = build_test_jpeg(64, 48, 0x77);

    // Pre-cancelled context must be immediately refused
    let cx = ReplayCx::for_test();
    cx.request_cancellation();

    let limits = MjpegLimits::default();
    let res = split_jpeg_stream(&frame, &limits, Some(&cx));
    assert_eq!(res, Err(JpegSplitError::CancellationRequested));

    let duration_ms = start.elapsed().as_millis().max(1);
    let cancellation_refused = res == Err(JpegSplitError::CancellationRequested);
    let (verdict, exit_code) = if cancellation_refused {
        ("pass", 0)
    } else {
        ("fail", 1)
    };
    let expected = r#"{"cancellation_refused":true,"error":"CancellationRequested"}"#;
    let observed = format!(
        r#"{{"cancellation_refused":{},"observed_error":"{:?}","duration_ms":{}}}"#,
        cancellation_refused, res, duration_ms
    );
    emit_caplog(
        "cancellation_checkpoints",
        verdict,
        exit_code,
        expected,
        &observed,
        duration_ms,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 2: Edge case: APPn and COM markers with embedded 0xFFD9
// ---------------------------------------------------------------------------

#[test]
fn test_edge_case_appn_com_ffd9_shielding() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let mut data = Vec::with_capacity(128);
    data.extend_from_slice(&[0xFF, 0xD8]); // SOI

    // APP1 (Exif-like) with embedded 0xFF, 0xD9 inside payload
    data.extend_from_slice(&[0xFF, 0xE1, 0x00, 0x06, 0xFF, 0xD9, 0x11, 0x22]);

    // COM (Comment) with embedded 0xFF, 0xD9 inside payload
    data.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x06, 0xFF, 0xD9, 0x33, 0x44]);

    // SOF0 (16x8, 1 component)
    data.extend(helper_sof0(16, 8)); // 11 bytes

    // SOS1 (1 component)
    data.extend(helper_sos1()); // 10 bytes

    // ECS
    data.extend_from_slice(&[0x42, 0x99]);

    // Real EOI
    data.extend_from_slice(&[0xFF, 0xD9]);

    let expected_len = data.len();
    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&data, &limits, None)?;

    assert_eq!(scan.frames.len(), 1);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, expected_len);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);
    assert_eq!(scan.frames[0].marker_count, 4); // APP1, COM, SOF0, SOS1
    assert_eq!(scan.findings, Vec::<JpegFinding>::new());

    let duration_ms = start.elapsed().as_millis().max(1);
    let passed = scan.frames.len() == 1
        && scan.frames[0].end_offset == expected_len
        && scan.frames[0].has_eoi
        && !scan.frames[0].is_truncated
        && scan.frames[0].marker_count == 4
        && scan.findings.is_empty();
    let (verdict, exit_code) = if passed {
        ("pass", 0)
    } else {
        ("fail", 1)
    };
    let expected = format!(
        r#"{{"frame_count":1,"end_offset":{},"has_eoi":true,"is_truncated":false,"findings_count":0}}"#,
        expected_len
    );
    let observed = format!(
        r#"{{"frame_count":{},"end_offset":{},"has_eoi":{},"is_truncated":{},"findings_count":{}}}"#,
        scan.frames.len(),
        scan.frames[0].end_offset,
        scan.frames[0].has_eoi,
        scan.frames[0].is_truncated,
        scan.findings.len()
    );
    emit_caplog(
        "edge_case_appn_com_ffd9_shielding",
        verdict,
        exit_code,
        &expected,
        &observed,
        duration_ms,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 3: Edge case: Byte stuffing (0xFF00) inside ECS (Kills M1)
// ---------------------------------------------------------------------------

#[test]
fn test_edge_case_byte_stuffing() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let ecs = [
        0x12, 0xFF, 0x00, 0xD9, 0x34, 0xFF, 0x00, 0xFF, 0x00, 0xD9, 0x56,
    ];
    let f = helper_frame(8, 8, &ecs); // 38 bytes

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&f, &limits, None)?;

    assert_eq!(scan.frames.len(), 1);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 38);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);
    assert_eq!(scan.frames[0].marker_count, 2);
    assert_eq!(scan.findings, Vec::<JpegFinding>::new());

    let duration_ms = start.elapsed().as_millis().max(1);
    let passed = scan.frames.len() == 1
        && scan.frames[0].end_offset == 38
        && scan.frames[0].has_eoi
        && !scan.frames[0].is_truncated
        && scan.frames[0].marker_count == 2
        && scan.findings.is_empty();
    let (verdict, exit_code) = if passed {
        ("pass", 0)
    } else {
        ("fail", 1)
    };
    let expected = r#"{"frame_count":1,"end_offset":38,"has_eoi":true,"is_truncated":false,"findings_count":0}"#;
    let observed = format!(
        r#"{{"frame_count":{},"end_offset":{},"has_eoi":{},"is_truncated":{},"findings_count":{}}}"#,
        scan.frames.len(),
        scan.frames[0].end_offset,
        scan.frames[0].has_eoi,
        scan.frames[0].is_truncated,
        scan.findings.len()
    );
    emit_caplog(
        "edge_case_byte_stuffing",
        verdict,
        exit_code,
        expected,
        &observed,
        duration_ms,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 4: Edge case: Restart markers RST0..RST7 in ECS and DRI (Kills M2)
// ---------------------------------------------------------------------------

#[test]
fn test_edge_case_restart_markers() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let mut ecs = Vec::new();
    for m in 0xD0u8..=0xD7 {
        ecs.extend_from_slice(&[0x01, 0xFF, m]);
    }
    ecs.extend_from_slice(&[0x09, 0xFF, 0xFF, 0xD3, 0x0A]); // 29 bytes

    let dri = [0xFF, 0xDD, 0x00, 0x04, 0x00, 0x04]; // 6 bytes
    let mut f = vec![0xFF, 0xD8];
    f.extend_from_slice(&dri);
    f.extend(helper_sof0(8, 8)); // 11 bytes
    f.extend(helper_sos1()); // 10 bytes
    f.extend_from_slice(&ecs); // 29 bytes
    f.extend_from_slice(&[0xFF, 0xD9]); // 2 bytes
    // Total length = 62 bytes

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&f, &limits, None)?;

    assert_eq!(scan.frames.len(), 1);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 62);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);
    assert_eq!(scan.frames[0].restart_interval, 4);
    assert_eq!(scan.frames[0].marker_count, 3); // DRI, SOF0, SOS1
    assert_eq!(scan.findings, Vec::<JpegFinding>::new());

    let duration_ms = start.elapsed().as_millis().max(1);
    let passed = scan.frames.len() == 1
        && scan.frames[0].end_offset == 62
        && scan.frames[0].restart_interval == 4
        && scan.frames[0].has_eoi
        && !scan.frames[0].is_truncated
        && scan.findings.is_empty();
    let (verdict, exit_code) = if passed {
        ("pass", 0)
    } else {
        ("fail", 1)
    };
    let expected = r#"{"frame_count":1,"end_offset":62,"restart_interval":4,"has_eoi":true,"is_truncated":false,"findings_count":0}"#;
    let observed = format!(
        r#"{{"frame_count":{},"end_offset":{},"restart_interval":{},"has_eoi":{},"is_truncated":{},"findings_count":{}}}"#,
        scan.frames.len(),
        scan.frames[0].end_offset,
        scan.frames[0].restart_interval,
        scan.frames[0].has_eoi,
        scan.frames[0].is_truncated,
        scan.findings.len()
    );
    emit_caplog(
        "edge_case_restart_markers",
        verdict,
        exit_code,
        expected,
        &observed,
        duration_ms,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 5: Edge case: Zero-length marker segment (length < 2) (Kills M8)
// ---------------------------------------------------------------------------

#[test]
fn test_edge_case_zero_length_segment() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let f = [0xFF, 0xD8, 0xFF, 0xFE, 0x00, 0x01, 0xFF, 0xD9]; // 8 bytes

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&f, &limits, None)?;

    assert_eq!(scan.frames.len(), 1);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 8);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);
    assert_eq!(scan.frames[0].marker_count, 1);
    assert_eq!(
        scan.findings,
        vec![JpegFinding::ZeroLengthMarkerSegment {
            frame_index: 0,
            marker: 0xFE,
            offset: 2,
        }]
    );

    let duration_ms = start.elapsed().as_millis().max(1);
    let zero_length_offset = match scan.findings.first() {
        Some(JpegFinding::ZeroLengthMarkerSegment { offset, .. }) => *offset,
        _ => 0,
    };
    let passed = scan.frames.len() == 1
        && scan.frames[0].end_offset == 8
        && scan.frames[0].marker_count == 1
        && zero_length_offset == 2;
    let (verdict, exit_code) = if passed {
        ("pass", 0)
    } else {
        ("fail", 1)
    };
    let expected = r#"{"frame_count":1,"end_offset":8,"marker_count":1,"zero_length_offset":2}"#;
    let observed = format!(
        r#"{{"frame_count":{},"end_offset":{},"marker_count":{},"zero_length_offset":{}}}"#,
        scan.frames.len(),
        scan.frames.first().map(|f| f.end_offset).unwrap_or(0),
        scan.frames.first().map(|f| f.marker_count).unwrap_or(0),
        zero_length_offset
    );
    emit_caplog(
        "edge_case_zero_length_segment",
        verdict,
        exit_code,
        expected,
        &observed,
        duration_ms,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 6: Edge case: Fill-byte runs before markers and EOI
// ---------------------------------------------------------------------------

#[test]
fn test_edge_case_fill_bytes_runs() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let mut f = vec![0xFF, 0xD8, 0xFF, 0xFF];
    f.extend(helper_sof0(16, 8));
    f.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
    f.extend(helper_sos1());
    f.extend_from_slice(&[0x11, 0x22, 0xFF, 0xFF, 0xFF, 0xD9]);

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&f, &limits, None)?;

    assert_eq!(scan.frames.len(), 1);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 36);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);
    assert_eq!(
        scan.frames[0].sof.as_ref().map(|s| (s.width, s.height)),
        Some((16, 8))
    );
    assert_eq!(scan.frames[0].marker_count, 2);
    assert_eq!(scan.findings, Vec::<JpegFinding>::new());

    let (width, height) = scan.frames[0]
        .sof
        .as_ref()
        .map(|s| (s.width, s.height))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing SOF"))?;

    let duration_ms = start.elapsed().as_millis().max(1);
    let passed = scan.frames.len() == 1
        && scan.frames[0].end_offset == 36
        && (width, height) == (16, 8)
        && scan.frames[0].marker_count == 2
        && scan.findings.is_empty();
    let (verdict, exit_code) = if passed {
        ("pass", 0)
    } else {
        ("fail", 1)
    };
    let expected = r#"{"frame_count":1,"end_offset":36,"dimensions":[16,8],"marker_count":2,"findings_count":0}"#;
    let observed = format!(
        r#"{{"frame_count":{},"end_offset":{},"dimensions":[{},{}],"marker_count":{},"findings_count":{}}}"#,
        scan.frames.len(),
        scan.frames[0].end_offset,
        width,
        height,
        scan.frames[0].marker_count,
        scan.findings.len()
    );
    emit_caplog(
        "edge_case_fill_bytes_runs",
        verdict,
        exit_code,
        expected,
        &observed,
        duration_ms,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 7: Edge case: SOF with 0 components
// ---------------------------------------------------------------------------

#[test]
fn test_edge_case_zero_components() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let mut sof = vec![0xFF, 0xC0, 0x00, 0x08, 0x08];
    sof.extend_from_slice(&8u16.to_be_bytes());
    sof.extend_from_slice(&8u16.to_be_bytes());
    sof.push(0); // 0 components

    let mut f = vec![0xFF, 0xD8];
    f.extend(sof);
    f.extend(helper_sos1());
    f.extend_from_slice(&[0x11, 0xFF, 0xD9]);

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&f, &limits, None)?;

    assert_eq!(scan.frames.len(), 1);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);
    assert_eq!(
        scan.findings,
        vec![JpegFinding::ZeroComponents {
            frame_index: 0,
            offset: 2,
        }]
    );

    let duration_ms = start.elapsed().as_millis().max(1);
    let zero_components_offset = match scan.findings.first() {
        Some(JpegFinding::ZeroComponents { offset, .. }) => *offset,
        _ => 0,
    };
    let zero_components_finding =
        matches!(scan.findings.first(), Some(JpegFinding::ZeroComponents { .. }));
    let passed = scan.frames.len() == 1 && zero_components_finding && zero_components_offset == 2;
    let (verdict, exit_code) = if passed {
        ("pass", 0)
    } else {
        ("fail", 1)
    };
    let expected = r#"{"frame_count":1,"zero_components_finding":true,"offset":2}"#;
    let observed = format!(
        r#"{{"frame_count":{},"zero_components_finding":{},"offset":{}}}"#,
        scan.frames.len(),
        zero_components_finding,
        zero_components_offset
    );
    emit_caplog(
        "edge_case_zero_components",
        verdict,
        exit_code,
        expected,
        &observed,
        duration_ms,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 8: Synthetic stream variants: clean, truncated, garbage, zero-length, dims (Kills M3)
// ---------------------------------------------------------------------------

#[test]
fn test_synthetic_stream_variants() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let limits = MjpegLimits::default();

    // Variant 1: Clean 3 frames
    let f1 = build_test_jpeg(16, 16, 0x11);
    let f2 = build_test_jpeg(32, 24, 0x22);
    let f3 = build_test_jpeg(64, 48, 0x33);
    let mut clean_stream = Vec::new();
    clean_stream.extend_from_slice(&f1);
    clean_stream.extend_from_slice(&f2);
    clean_stream.extend_from_slice(&f3);
    let scan_clean = split_jpeg_stream(&clean_stream, &limits, None)?;
    assert_eq!(scan_clean.frame_count(), 3);
    assert_eq!(scan_clean.valid_frame_count(), 3);
    assert!(!scan_clean.has_truncation());
    assert!(!scan_clean.has_omissions());
    assert!(scan_clean.findings.is_empty());

    // Variant 2: Truncated last frame (kills M3)
    let mut trunc_last = Vec::new();
    trunc_last.extend_from_slice(&f1);
    trunc_last.extend_from_slice(&f2);
    let f3_cut_start = trunc_last.len();
    // f3 truncated before EOI
    trunc_last.extend_from_slice(&[0xFF, 0xD8]);
    trunc_last.extend(helper_sof0(64, 48));
    trunc_last.extend(helper_sos1());
    trunc_last.extend_from_slice(&[0x33, 0x44]);
    let trunc_last_len = trunc_last.len();

    let scan_trunc = split_jpeg_stream(&trunc_last, &limits, None)?;
    assert_eq!(scan_trunc.frame_count(), 3);
    assert_eq!(scan_trunc.valid_frame_count(), 2);
    assert!(scan_trunc.has_truncation());
    assert!(scan_trunc.frames[2].is_truncated);
    assert!(!scan_trunc.frames[2].has_eoi);
    assert_eq!(scan_trunc.frames[2].start_offset, f3_cut_start);
    assert_eq!(scan_trunc.frames[2].end_offset, trunc_last_len);
    assert_eq!(
        scan_trunc.findings,
        vec![JpegFinding::TruncatedFrame {
            frame_index: 2,
            start_offset: f3_cut_start,
            end_offset: trunc_last_len,
        }]
    );

    // Variant 3: Garbage between frames
    let mut junk_stream = Vec::new();
    junk_stream.extend_from_slice(&f1);
    junk_stream.extend_from_slice(b"JUNK1");
    junk_stream.extend_from_slice(&f2);
    junk_stream.extend_from_slice(b"JUNK2");
    junk_stream.extend_from_slice(&f3);
    let scan_junk = split_jpeg_stream(&junk_stream, &limits, None)?;
    assert_eq!(scan_junk.frame_count(), 3);
    let o1_start = f1.len();
    let o1_end = f1.len() + 5;
    let o2_start = o1_end + f2.len();
    let o2_end = o2_start + 5;

    assert_eq!(
        scan_junk.omissions,
        vec![
            OmissionSpan {
                start_offset: o1_start,
                end_offset: o1_end,
                reason: OmissionReason::GarbageBetweenFrames,
            },
            OmissionSpan {
                start_offset: o2_start,
                end_offset: o2_end,
                reason: OmissionReason::GarbageBetweenFrames,
            },
        ]
    );
    assert_eq!(
        scan_junk.findings,
        vec![
            JpegFinding::GarbageBetweenFrames {
                preceding_frame_index: 0,
                start_offset: o1_start,
                end_offset: o1_end,
            },
            JpegFinding::GarbageBetweenFrames {
                preceding_frame_index: 1,
                start_offset: o2_start,
                end_offset: o2_end,
            },
        ]
    );

    // Variant 4: Zero length stream
    let res_zero = split_jpeg_stream(&[], &limits, None);
    assert_eq!(res_zero, Err(JpegSplitError::NoSoi));

    // Variant 5: Dimension change across frames
    let mut dim_stream = Vec::new();
    dim_stream.extend_from_slice(&f1); // 16x16
    dim_stream.extend_from_slice(&f3); // 64x48
    let scan_dim = split_jpeg_stream(&dim_stream, &limits, None)?;
    assert_eq!(scan_dim.frame_count(), 2);
    assert_eq!(
        scan_dim.frames[0].sof.as_ref().map(|s| (s.width, s.height)),
        Some((16, 16))
    );
    assert_eq!(
        scan_dim.frames[1].sof.as_ref().map(|s| (s.width, s.height)),
        Some((64, 48))
    );

    let duration_ms = start.elapsed().as_millis().max(1);
    let passed = scan_clean.frame_count() == 3
        && scan_trunc.frame_count() == 3
        && scan_junk.frame_count() == 3
        && scan_junk.omissions.len() == 2
        && scan_junk.findings.len() == 2
        && res_zero == Err(JpegSplitError::NoSoi)
        && scan_dim.frame_count() == 2;
    let (verdict, exit_code) = if passed {
        ("pass", 0)
    } else {
        ("fail", 1)
    };
    let expected = r#"{"variants_tested":5,"clean_frames":3,"truncated_valid":2,"omissions":2,"zero_len_error":"NoSoi"}"#;
    let observed = format!(
        r#"{{"variants_tested":5,"clean_frames":{},"truncated_valid":{},"omissions":{},"zero_len_error":"{:?}"}}"#,
        scan_clean.valid_frame_count(),
        scan_trunc.valid_frame_count(),
        scan_junk.omissions.len(),
        res_zero
    );
    emit_caplog(
        "synthetic_stream_variants",
        verdict,
        exit_code,
        expected,
        &observed,
        duration_ms,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 9: Fixture manifest equality and delegated JPEG fixtures
// ---------------------------------------------------------------------------

#[test]
fn test_fixture_manifest_equality() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    let manifest_path = repo_root.join("tests/fixtures/media/mjpeg/fixture_manifest.json");
    if !manifest_path.exists() {
        let duration_ms = start.elapsed().as_millis().max(1);
        let expected = r#"{"fixture_manifest_available":true}"#;
        let observed =
            r#"{"fixture_manifest_available":false,"reason":"missing .5 fixture files on disk"}"#;
        emit_caplog(
            "fixture_manifest_equality",
            "skip",
            0,
            expected,
            observed,
            duration_ms,
        );
        return Ok(());
    }

    let manifest_bytes = fs::read(&manifest_path)?;
    let manifest_val = parse_json(&manifest_bytes)?;
    assert_eq!(
        manifest_val.get("schema").and_then(|s| s.as_str()),
        Some("fss.mjpeg_fixture_manifest.v1")
    );
    let fixtures = manifest_val
        .get("fixtures")
        .and_then(|f| f.as_array())
        .ok_or("expected fixtures array")?;

    let mjpeg_dir = repo_root.join("tests/fixtures/media/mjpeg");
    let limits = MjpegLimits::default();
    let mut verified_count = 0;

    for f in fixtures {
        let name = f
            .get("name")
            .and_then(|s| s.as_str())
            .ok_or("missing name")?;
        let expected_frame_count = f
            .get("frame_count")
            .and_then(|n| n.as_i64())
            .ok_or("missing frame_count")? as usize;
        let expected_file_sha = f
            .get("file_sha256")
            .and_then(|s| s.as_str())
            .ok_or("missing file_sha256")?;
        let expected_file_size = f
            .get("file_size")
            .and_then(|n| n.as_i64())
            .ok_or("missing file_size")? as usize;

        let file_path = mjpeg_dir.join(name);
        let bytes = fs::read(&file_path)?;
        assert_eq!(
            bytes.len(),
            expected_file_size,
            "file_size mismatch for {name}"
        );

        let actual_sha = sha256_hex(&bytes);
        assert_eq!(
            actual_sha, expected_file_sha,
            "file_sha256 mismatch for {name}"
        );

        if expected_file_size == 0 {
            let res = split_jpeg_stream(&bytes, &limits, None);
            assert_eq!(res, Err(JpegSplitError::NoSoi));
            verified_count += 1;
            continue;
        }

        let scan = split_jpeg_stream(&bytes, &limits, None)?;
        assert_eq!(
            scan.frame_count(),
            expected_frame_count,
            "frame_count mismatch for {name}"
        );

        if expected_frame_count > 0 {
            let expected_frames = f
                .get("frames")
                .and_then(|fr| fr.as_array())
                .ok_or("missing required frames array in fixture schema")?;
            assert_eq!(scan.frames.len(), expected_frames.len());
            for (idx, ef) in expected_frames.iter().enumerate() {
                let exp_w = ef
                    .get("width")
                    .and_then(|n| n.as_i64())
                    .ok_or("missing width")? as u16;
                let exp_h = ef
                    .get("height")
                    .and_then(|n| n.as_i64())
                    .ok_or("missing height")? as u16;
                let sof = scan.frames[idx].sof.as_ref().ok_or("missing SOF")?;
                assert_eq!(sof.width, exp_w, "width mismatch for {name} frame {idx}");
                assert_eq!(sof.height, exp_h, "height mismatch for {name} frame {idx}");
            }
        }
        verified_count += 1;
    }

    let duration_ms = start.elapsed().as_millis().max(1);
    let expected = format!(
        r#"{{"fixture_manifest_available":true,"fixtures_count":{}}}"#,
        fixtures.len()
    );
    let observed = format!(
        r#"{{"fixture_manifest_available":true,"verified_fixtures":{}}}"#,
        verified_count
    );
    let passed = verified_count == fixtures.len();
    let (verdict, exit_code) = if passed {
        ("pass", 0)
    } else {
        ("fail", 1)
    };
    emit_caplog(
        "fixture_manifest_equality",
        verdict,
        exit_code,
        &expected,
        &observed,
        duration_ms,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 9b: Delegated .21 JPEG fixtures verification
// ---------------------------------------------------------------------------

#[test]
fn test_delegated_jpeg_fixtures() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    let jpeg_dir = repo_root.join("tests/fixtures/media/jpeg");
    let app_com = jpeg_dir.join("rgb_64x48_app_com_ffd9.jpg");
    let restart = jpeg_dir.join("rgb_64x48_restart_ri3.jpg");

    if !jpeg_dir.exists() || !app_com.exists() || !restart.exists() {
        let duration_ms = start.elapsed().as_millis().max(1);
        let expected = r#"{"delegated_fixtures_available":true}"#;
        let observed =
            r#"{"delegated_fixtures_available":false,"reason":"missing .21 jpeg fixture files on disk"}"#;
        emit_caplog(
            "delegated_jpeg_fixtures",
            "skip",
            0,
            expected,
            observed,
            duration_ms,
        );
        return Ok(());
    }

    let limits = MjpegLimits::default();
    let bytes_app = fs::read(&app_com)?;
    let scan_app = split_jpeg_stream(&bytes_app, &limits, None)?;
    assert_eq!(scan_app.frame_count(), 1);
    let sof_app = scan_app.frames[0].sof.as_ref().ok_or("missing SOF")?;
    assert_eq!(sof_app.width, 64);
    assert_eq!(sof_app.height, 48);

    let bytes_restart = fs::read(&restart)?;
    let scan_restart = split_jpeg_stream(&bytes_restart, &limits, None)?;
    assert_eq!(scan_restart.frame_count(), 1);
    assert_eq!(scan_restart.frames[0].restart_interval, 3);
    let sof_restart = scan_restart.frames[0].sof.as_ref().ok_or("missing SOF")?;
    assert_eq!(sof_restart.width, 64);
    assert_eq!(sof_restart.height, 48);

    let duration_ms = start.elapsed().as_millis().max(1);
    let expected = r#"{"delegated_fixtures_available":true,"fixtures_verified":2}"#;
    let observed = r#"{"delegated_fixtures_available":true,"fixtures_verified":2}"#;
    emit_caplog(
        "delegated_jpeg_fixtures",
        "pass",
        0,
        expected,
        observed,
        duration_ms,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 10: Malformed gauntlet: Leading, inter-frame, and trailing omissions
// ---------------------------------------------------------------------------

#[test]
fn test_gauntlet_omissions_and_garbage() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let f1 = build_test_jpeg(16, 16, 0x11);
    let f2 = build_test_jpeg(32, 24, 0x22);
    let len1 = f1.len();
    let len2 = f2.len();

    let mut stream = Vec::new();
    stream.extend_from_slice(b"LEAD"); // 0..4
    stream.extend_from_slice(&f1); // 4..(4+len1)
    stream.extend_from_slice(b"MID"); // (4+len1)..(7+len1)
    stream.extend_from_slice(&f2); // (7+len1)..(7+len1+len2)
    stream.extend_from_slice(b"TRAIL"); // (7+len1+len2)..total
    let total_len = stream.len();

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&stream, &limits, None)?;

    assert_eq!(scan.frames.len(), 2);
    assert_eq!(scan.omissions.len(), 3);
    assert_eq!(
        scan.omissions[0],
        OmissionSpan {
            start_offset: 0,
            end_offset: 4,
            reason: OmissionReason::GarbageBeforeFirstSoi,
        }
    );
    assert_eq!(
        scan.omissions[1],
        OmissionSpan {
            start_offset: 4 + len1,
            end_offset: 7 + len1,
            reason: OmissionReason::GarbageBetweenFrames,
        }
    );
    assert_eq!(
        scan.omissions[2],
        OmissionSpan {
            start_offset: 7 + len1 + len2,
            end_offset: total_len,
            reason: OmissionReason::TrailingGarbage,
        }
    );
    assert_eq!(
        scan.findings,
        vec![
            JpegFinding::GarbageBeforeFirstSoi {
                start_offset: 0,
                end_offset: 4,
            },
            JpegFinding::GarbageBetweenFrames {
                preceding_frame_index: 0,
                start_offset: 4 + len1,
                end_offset: 7 + len1,
            },
            JpegFinding::TrailingGarbage {
                start_offset: 7 + len1 + len2,
                end_offset: total_len,
            },
        ]
    );

    let duration_ms = start.elapsed().as_millis().max(1);
    let passed = scan.frames.len() == 2 && scan.omissions.len() == 3 && scan.findings.len() == 3;
    let (verdict, exit_code) = if passed {
        ("pass", 0)
    } else {
        ("fail", 1)
    };
    let expected = r#"{"frames":2,"omissions":3,"findings":3}"#;
    let observed = format!(
        r#"{{"frames":{},"omissions":{},"findings":{}}}"#,
        scan.frames.len(),
        scan.omissions.len(),
        scan.findings.len()
    );
    emit_caplog(
        "gauntlet_omissions_and_garbage",
        verdict,
        exit_code,
        expected,
        &observed,
        duration_ms,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 11: In-frame anomalies: garbage, stray stuffing, short SOF, zero height, DNL
// ---------------------------------------------------------------------------

#[test]
fn test_gauntlet_in_frame_anomalies() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let mut data = Vec::with_capacity(256);
    data.extend_from_slice(&[0xFF, 0xD8]); // SOI (0..2)

    // In-frame garbage between marker segments (2..5)
    data.extend_from_slice(&[0x12, 0x34, 0x56]);

    // Stray FF00 sequence outside scan data (5..7)
    data.extend_from_slice(&[0xFF, 0x00]);

    // Short SOF segment (< 8 bytes) (7..14)
    data.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x05, 0x08, 0x00, 0x10]);

    // Zero height SOF (DNL) (14..27)
    data.extend_from_slice(&[
        0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x00, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00,
    ]);

    // Unsupported DNL marker (27..33)
    data.extend_from_slice(&[0xFF, 0xDC, 0x00, 0x04, 0x00, 0x10]);

    // EOI (33..35)
    data.extend_from_slice(&[0xFF, 0xD9]);

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&data, &limits, None)?;

    assert_eq!(scan.frames.len(), 1);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 35);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);
    assert_eq!(scan.frames[0].marker_count, 5);

    assert_eq!(
        scan.findings,
        vec![
            JpegFinding::GarbageInsideFrame {
                frame_index: 0,
                start_offset: 2,
                end_offset: 5,
            },
            JpegFinding::StrayByteStuffing {
                frame_index: 0,
                offset: 5,
            },
            JpegFinding::ShortMarkerSegment {
                frame_index: 0,
                marker: 0xC0,
                offset: 7,
                length: 5,
            },
            JpegFinding::ZeroHeightSof {
                frame_index: 0,
                offset: 14,
            },
            JpegFinding::DnlMarkerUnsupported {
                frame_index: 0,
                offset: 27,
            },
        ]
    );

    let duration_ms = start.elapsed().as_millis().max(1);
    let passed = scan.frames.len() == 1
        && scan.frames[0].end_offset == 35
        && scan.frames[0].marker_count == 5
        && scan.findings.len() == 5;
    let (verdict, exit_code) = if passed {
        ("pass", 0)
    } else {
        ("fail", 1)
    };
    let expected = r#"{"frame_count":1,"end_offset":35,"findings_count":5}"#;
    let observed = format!(
        r#"{{"frame_count":{},"end_offset":{},"findings_count":{}}}"#,
        scan.frames.len(),
        scan.frames[0].end_offset,
        scan.findings.len()
    );
    emit_caplog(
        "gauntlet_in_frame_anomalies",
        verdict,
        exit_code,
        expected,
        &observed,
        duration_ms,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 12: Limits enforcement boundaries (Kills M7)
// ---------------------------------------------------------------------------

#[test]
fn test_limits_enforcement_boundaries() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let frame = build_test_jpeg(64, 48, 0x55);
    let frame_len = frame.len();

    // 12.1 max_input_bytes boundary
    let exact_input_limits = MjpegLimits {
        max_input_bytes: frame_len,
        ..MjpegLimits::default()
    };
    let scan_in = split_jpeg_stream(&frame, &exact_input_limits, None)?;
    assert_eq!(scan_in.frames.len(), 1);

    let too_small_input_limits = MjpegLimits {
        max_input_bytes: frame_len - 1,
        ..MjpegLimits::default()
    };
    let res_in = split_jpeg_stream(&frame, &too_small_input_limits, None);
    assert_eq!(
        res_in,
        Err(JpegSplitError::InputOversized {
            size: frame_len,
            limit: frame_len - 1,
        })
    );

    // 12.2 max_frame_bytes boundary
    let exact_frame_limits = MjpegLimits {
        max_frame_bytes: frame_len,
        ..MjpegLimits::default()
    };
    let scan_fr = split_jpeg_stream(&frame, &exact_frame_limits, None)?;
    assert_eq!(scan_fr.frames.len(), 1);

    let too_small_frame_limits = MjpegLimits {
        max_frame_bytes: frame_len - 1,
        ..MjpegLimits::default()
    };
    let res_fr = split_jpeg_stream(&frame, &too_small_frame_limits, None);
    assert_eq!(
        res_fr,
        Err(JpegSplitError::FrameTooLarge {
            frame_index: 0,
            size: frame_len,
            limit: frame_len - 1,
        })
    );

    // 12.3 max_dimension boundary on standard frame
    let exact_dim_limits = MjpegLimits {
        max_dimension: 64,
        ..MjpegLimits::default()
    };
    let scan_dim = split_jpeg_stream(&frame, &exact_dim_limits, None)?;
    assert_eq!(scan_dim.frames.len(), 1);

    let too_small_dim_limits = MjpegLimits {
        max_dimension: 63,
        ..MjpegLimits::default()
    };
    let res_dim = split_jpeg_stream(&frame, &too_small_dim_limits, None);
    assert_eq!(
        res_dim,
        Err(JpegSplitError::DimensionLimit {
            width: 64,
            height: 48,
            max_dimension: 63,
        })
    );

    // Height dimension boundary
    let too_small_height_limits = MjpegLimits {
        max_dimension: 47,
        ..MjpegLimits::default()
    };
    let res_height = split_jpeg_stream(&frame, &too_small_height_limits, None);
    assert_eq!(
        res_height,
        Err(JpegSplitError::DimensionLimit {
            width: 64,
            height: 48,
            max_dimension: 47,
        })
    );

    // 12.4 Oversize dimensions (Kills M7)
    let wide_frame = helper_frame(16385, 8, &[0x11]);
    let res_wide = split_jpeg_stream(&wide_frame, &MjpegLimits::default(), None);
    assert_eq!(
        res_wide,
        Err(JpegSplitError::DimensionLimit {
            width: 16385,
            height: 8,
            max_dimension: 16384,
        })
    );

    let tall_frame = helper_frame(8, 16385, &[0x11]);
    let res_tall = split_jpeg_stream(&tall_frame, &MjpegLimits::default(), None);
    assert_eq!(
        res_tall,
        Err(JpegSplitError::DimensionLimit {
            width: 8,
            height: 16385,
            max_dimension: 16384,
        })
    );

    // 12.5 max_frames boundary
    let f1 = build_test_jpeg(16, 16, 0x01);
    let f2 = build_test_jpeg(16, 16, 0x02);
    let mut two_frames = Vec::new();
    two_frames.extend_from_slice(&f1);
    two_frames.extend_from_slice(&f2);

    let limit_one_frame = MjpegLimits {
        max_frames: 1,
        ..MjpegLimits::default()
    };
    let res_frames = split_jpeg_stream(&two_frames, &limit_one_frame, None);
    assert_eq!(
        res_frames,
        Err(JpegSplitError::TooManyFrames { count: 2, limit: 1 })
    );

    let duration_ms = start.elapsed().as_millis().max(1);
    let all_boundaries_verified = matches!(res_in, Err(JpegSplitError::InputOversized { .. }))
        && matches!(res_fr, Err(JpegSplitError::FrameTooLarge { .. }))
        && matches!(res_dim, Err(JpegSplitError::DimensionLimit { .. }))
        && matches!(res_height, Err(JpegSplitError::DimensionLimit { .. }))
        && matches!(res_wide, Err(JpegSplitError::DimensionLimit { .. }))
        && matches!(res_tall, Err(JpegSplitError::DimensionLimit { .. }))
        && matches!(res_frames, Err(JpegSplitError::TooManyFrames { .. }));

    let err_names: Vec<&str> = vec![
        match &res_in { Err(JpegSplitError::InputOversized { .. }) => "InputOversized", _ => "Other" },
        match &res_fr { Err(JpegSplitError::FrameTooLarge { .. }) => "FrameTooLarge", _ => "Other" },
        match &res_dim { Err(JpegSplitError::DimensionLimit { .. }) => "DimensionLimit", _ => "Other" },
        match &res_frames { Err(JpegSplitError::TooManyFrames { .. }) => "TooManyFrames", _ => "Other" },
    ];
    let err_names_json = format!(r#"["{}","{}","{}","{}"]"#, err_names[0], err_names[1], err_names[2], err_names[3]);
    let (verdict, exit_code) = if all_boundaries_verified {
        ("pass", 0)
    } else {
        ("fail", 1)
    };
    let expected = r#"{"boundaries_tested":["max_input_bytes","max_frame_bytes","max_dimension","max_frames"]}"#;
    let observed = format!(
        r#"{{"all_boundaries_verified":{},"tested_errors":{},"duration_ms":{}}}"#,
        all_boundaries_verified,
        err_names_json,
        duration_ms
    );
    emit_caplog(
        "limits_enforcement_boundaries",
        verdict,
        exit_code,
        expected,
        &observed,
        duration_ms,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 13: Middle frame overflow resyncs at next SOI
// ---------------------------------------------------------------------------

#[test]
fn test_gauntlet_middle_frame_resync() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let f1 = build_test_jpeg(16, 16, 0x11);
    let f3 = build_test_jpeg(16, 16, 0x33);

    let mut stream = Vec::new();
    stream.extend_from_slice(&f1);

    let f2_start = stream.len();
    // Frame 2: SOI, then APP0 with declared length 0xFFFF (exceeding available bytes)
    stream.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0, 0xFF, 0xFF, 0xAA, 0xBB]);

    let f3_start = stream.len();
    stream.extend_from_slice(&f3);
    let total_len = stream.len();

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&stream, &limits, None)?;

    assert_eq!(scan.frames.len(), 3);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, f2_start);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);

    assert_eq!(scan.frames[1].start_offset, f2_start);
    assert_eq!(scan.frames[1].end_offset, f3_start);
    assert!(!scan.frames[1].has_eoi);
    assert!(scan.frames[1].is_truncated);

    assert_eq!(scan.frames[2].start_offset, f3_start);
    assert_eq!(scan.frames[2].end_offset, total_len);
    assert!(scan.frames[2].has_eoi);
    assert!(!scan.frames[2].is_truncated);

    let available = stream.len().saturating_sub(f2_start + 4);
    assert_eq!(
        scan.findings,
        vec![
            JpegFinding::MarkerLengthOverflow {
                frame_index: 1,
                offset: f2_start + 2,
                marker: 0xE0,
                length: 65535,
                available,
            },
            JpegFinding::TruncatedFrame {
                frame_index: 1,
                start_offset: f2_start,
                end_offset: f3_start,
            },
        ]
    );

    let duration_ms = start.elapsed().as_millis().max(1);
    let resync_success = scan.frames.len() == 3
        && scan.frames.get(1).map(|f| f.is_truncated).unwrap_or(false)
        && scan.frames.get(2).map(|f| !f.is_truncated).unwrap_or(false);
    let (verdict, exit_code) = if resync_success {
        ("pass", 0)
    } else {
        ("fail", 1)
    };
    let expected = r#"{"resync_success":true,"recovered_frames":3,"frame_1_truncated":true}"#;
    let observed = format!(
        r#"{{"resync_success":{},"recovered_frames":{},"frame_1_truncated":{}}}"#,
        resync_success,
        scan.frames.len(),
        scan.frames.get(1).map(|f| f.is_truncated).unwrap_or(false)
    );
    emit_caplog(
        "gauntlet_middle_frame_resync",
        verdict,
        exit_code,
        expected,
        &observed,
        duration_ms,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 14: Flood limits: exact boundary and garbage runs (Kills M5, M6)
// ---------------------------------------------------------------------------

#[test]
fn test_gauntlet_flood_limits() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let limits = MjpegLimits {
        max_marker_segments_per_frame: 3,
        ..MjpegLimits::default()
    };

    // 14.1 Exact boundary test: exactly 3 markers against limit 3 MUST SUCCEED (Kills M6)
    let mut frame_exact_3 = Vec::new();
    frame_exact_3.extend_from_slice(&[0xFF, 0xD8]); // SOI
    for _ in 0..3 {
        frame_exact_3.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x04, 0xAA, 0xBB]); // 3 COM markers
    }
    frame_exact_3.extend_from_slice(&[0xFF, 0xD9]); // EOI

    let scan_3 = split_jpeg_stream(&frame_exact_3, &limits, None)?;
    assert_eq!(scan_3.frames.len(), 1);
    assert_eq!(scan_3.frames[0].marker_count, 3);
    assert!(scan_3.frames[0].has_eoi);

    // 14.2 Exceeding boundary: exactly 4 markers against limit 3 MUST FAIL with count 4
    let mut frame_exceed_4 = Vec::new();
    frame_exceed_4.extend_from_slice(&[0xFF, 0xD8]);
    for _ in 0..4 {
        frame_exceed_4.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x04, 0xAA, 0xBB]);
    }
    frame_exceed_4.extend_from_slice(&[0xFF, 0xD9]);

    let res_exceed = split_jpeg_stream(&frame_exceed_4, &limits, None);
    assert_eq!(
        res_exceed,
        Err(JpegSplitError::TooManyMarkerSegments {
            frame_index: 0,
            count: 4,
            limit: 3,
        })
    );

    // 14.3 In-frame garbage run counted toward marker limit (Kills M5)
    // Stream has: SOI, 1 garbage byte (count 1), 1 stray 0xFF00 (count 2), SOF0 (count 3), SOS1 (count 4 -> error!)
    let mut mix = vec![0xFF, 0xD8, b'g', 0xFF, 0x00];
    mix.extend(helper_sof0(8, 8));
    mix.extend(helper_sos1());
    mix.extend_from_slice(&[0x11, 0xFF, 0xD9]);

    let res_garb = split_jpeg_stream(&mix, &limits, None);
    assert_eq!(
        res_garb,
        Err(JpegSplitError::TooManyMarkerSegments {
            frame_index: 0,
            count: 4,
            limit: 3,
        })
    );

    let duration_ms = start.elapsed().as_millis().max(1);
    let cap_boundary_exact_3_passes = scan_3.is_ok();
    let exceed_4_fails = matches!(
        res_exceed,
        Err(JpegSplitError::TooManyMarkerSegments {
            count: 4,
            limit: 3,
            ..
        })
    );
    let garbage_run_counted = matches!(
        res_garb,
        Err(JpegSplitError::TooManyMarkerSegments {
            count: 4,
            limit: 3,
            ..
        })
    );
    let passed = cap_boundary_exact_3_passes && exceed_4_fails && garbage_run_counted;
    let (verdict, exit_code) = if passed {
        ("pass", 0)
    } else {
        ("fail", 1)
    };
    let expected =
        r#"{"cap_boundary_exact_3_passes":true,"exceed_4_fails":true,"garbage_run_counted":true}"#;
    let observed = format!(
        r#"{{"cap_boundary_exact_3_passes":{},"exceed_4_fails":{},"garbage_run_counted":{}}}"#,
        cap_boundary_exact_3_passes, exceed_4_fails, garbage_run_counted
    );
    emit_caplog(
        "gauntlet_flood_limits",
        verdict,
        exit_code,
        expected,
        &observed,
        duration_ms,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 15: 10k mutation no-panic gauntlet with full invariant verification (F5)
// ---------------------------------------------------------------------------

#[test]
fn test_mutation_gauntlet_10k() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let mut prng = DeterministicFaultPrng::new(0x5F53_534D_4A50_4547);

    let f1 = build_test_jpeg(16, 16, 0xAA);
    let f2 = build_test_jpeg(32, 24, 0xBB);
    let mut template = Vec::with_capacity(f1.len() + f2.len() + 16);
    template.extend_from_slice(&f1);
    template.extend_from_slice(b"GARBAGE");
    template.extend_from_slice(&f2);

    let limits = MjpegLimits {
        max_input_bytes: 65536,
        max_frame_bytes: 32768,
        max_frames: 50,
        max_marker_segments_per_frame: 64,
        max_dimension: 1024,
    };

    let mut successful_scans = 0usize;
    let iterations = 10_000;

    for _ in 0..iterations {
        let mut mutated = template.clone();
        let mutation_count = (prng.next_u64() % 8) as usize + 1;

        for _ in 0..mutation_count {
            let op = prng.next_u64() % 4;
            match op {
                0 => {
                    // Byte flip
                    if !mutated.is_empty() {
                        let idx = (prng.next_u64() as usize) % mutated.len();
                        let val = prng.next_u64() as u8;
                        mutated[idx] = val;
                    }
                }
                1 => {
                    // Truncation
                    if mutated.len() > 2 {
                        let new_len = (prng.next_u64() as usize) % mutated.len();
                        mutated.truncate(new_len);
                    }
                }
                2 => {
                    // Insertion of JPEG markers or random noise
                    let idx = if mutated.is_empty() {
                        0
                    } else {
                        (prng.next_u64() as usize) % mutated.len()
                    };
                    let choices = [
                        &[0xFF, 0xD8][..],
                        &[0xFF, 0xD9][..],
                        &[0xFF, 0x00][..],
                        &[0xFF, 0xC0, 0x00, 0x03][..],
                        &[0xDE, 0xAD, 0xBE, 0xEF][..],
                    ];
                    let snippet = choices[(prng.next_u64() as usize) % choices.len()];
                    mutated.splice(idx..idx, snippet.iter().copied());
                }
                _ => {
                    // Chunk deletion
                    if mutated.len() > 4 {
                        let start_del = (prng.next_u64() as usize) % (mutated.len() - 2);
                        let del_len =
                            ((prng.next_u64() as usize) % 16).min(mutated.len() - start_del);
                        mutated.drain(start_del..(start_del + del_len));
                    }
                }
            }
        }

        // Must never panic!
        if let Ok(scan) = split_jpeg_stream(&mutated, &limits, None) {
            successful_scans += 1;

            // Invariant assertions on every Ok
            assert_eq!(scan.total_bytes_scanned, mutated.len());

            // 1. Validate frames: ordered, non-overlapping, within bounds
            let mut prev_frame_end = 0;
            for (idx, frame) in scan.frames.iter().enumerate() {
                assert_eq!(frame.frame_index, idx);
                assert!(frame.start_offset >= prev_frame_end);
                assert!(frame.start_offset <= frame.end_offset);
                assert!(frame.end_offset <= scan.total_bytes_scanned);
                prev_frame_end = frame.end_offset;
            }

            // 2. Validate omissions: ordered, non-overlapping, within bounds
            let mut prev_om_end = 0;
            for om in &scan.omissions {
                assert!(om.start_offset >= prev_om_end);
                assert!(om.start_offset < om.end_offset);
                assert!(om.end_offset <= scan.total_bytes_scanned);
                prev_om_end = om.end_offset;
            }

            // 3. Combined frames + omissions tile the scanned range without gaps
            let mut all_spans: Vec<(usize, usize)> = Vec::new();
            for f in &scan.frames {
                if f.start_offset < f.end_offset {
                    all_spans.push((f.start_offset, f.end_offset));
                }
            }
            for om in &scan.omissions {
                all_spans.push((om.start_offset, om.end_offset));
            }
            all_spans.sort_unstable_by_key(|(s, _)| *s);

            let mut cur_offset = 0;
            for (s, e) in all_spans {
                assert_eq!(s, cur_offset, "tiling gap/overlap in stream");
                cur_offset = e;
            }
            assert_eq!(cur_offset, scan.total_bytes_scanned);

            // 4. Finding offsets in bounds
            for finding in &scan.findings {
                let off = match finding {
                    JpegFinding::GarbageBeforeFirstSoi { start_offset, .. } => *start_offset,
                    JpegFinding::GarbageBetweenFrames { start_offset, .. } => *start_offset,
                    JpegFinding::TrailingGarbage { start_offset, .. } => *start_offset,
                    JpegFinding::TruncatedFrame { start_offset, .. } => *start_offset,
                    JpegFinding::ZeroLengthMarkerSegment { offset, .. } => *offset,
                    JpegFinding::ZeroComponents { offset, .. } => *offset,
                    JpegFinding::DuplicateSof { offset, .. } => *offset,
                    JpegFinding::GarbageInsideFrame { start_offset, .. } => *start_offset,
                    JpegFinding::StrayByteStuffing { offset, .. } => *offset,
                    JpegFinding::MarkerLengthOverflow { offset, .. } => *offset,
                    JpegFinding::ShortMarkerSegment { offset, .. } => *offset,
                    JpegFinding::ZeroHeightSof { offset, .. } => *offset,
                    JpegFinding::DnlMarkerUnsupported { offset, .. } => *offset,
                };
                assert!(off <= scan.total_bytes_scanned);
            }
        }
    }

    let duration_ms = start.elapsed().as_millis().max(1);
    let observed_panics: usize = 0;
    let passed = iterations == 10_000 && observed_panics == 0;
    let (verdict, exit_code) = if passed {
        ("pass", 0)
    } else {
        ("fail", 1)
    };
    let expected = format!(r#"{{"iterations":{iterations},"panics":0}}"#);
    let observed = format!(
        r#"{{"iterations":{},"panics":{},"successful_scans":{},"duration_ms":{}}}"#,
        iterations, observed_panics, successful_scans, duration_ms
    );
    emit_caplog(
        "mutation_gauntlet_10k",
        verdict,
        exit_code,
        &expected,
        &observed,
        duration_ms,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 16: Cut headers right after marker code and high length byte (Kills M4)
// ---------------------------------------------------------------------------

#[test]
fn test_gauntlet_cut_headers() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let limits = MjpegLimits::default();

    // 16.1 Cut right after marker code (Kills M4)
    // frame 0: 0..28 (clean)
    // frame 1 cut header: 28..32 (FF D8 FF E0; next frame's SOI read as declared length 0xFFD8)
    // frame 2: 32..60 (clean; MUST NOT be swallowed by resync)
    let mut s1 = helper_frame(8, 8, &[0x11]); // 28 bytes
    s1.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]); // 4 bytes
    s1.extend(helper_frame(8, 8, &[0x22])); // 28 bytes

    let scan1 = split_jpeg_stream(&s1, &limits, None)?;
    let spans1: Vec<(usize, usize, bool, bool)> = scan1
        .frames
        .iter()
        .map(|f| (f.start_offset, f.end_offset, f.has_eoi, f.is_truncated))
        .collect();
    assert_eq!(
        spans1,
        vec![
            (0, 28, true, false),
            (28, 32, false, true),
            (32, 60, true, false),
        ],
        "complete frame at 32..60 swallowed under cut after marker code"
    );

    // 16.2 Cut after high length byte
    let mut s2 = helper_frame(8, 8, &[0x11]); // 28 bytes
    s2.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00]); // 5 bytes: length 0x00FF overflows
    s2.extend(helper_frame(8, 8, &[0x22])); // 28 bytes

    let scan2 = split_jpeg_stream(&s2, &limits, None)?;
    let spans2: Vec<(usize, usize, bool, bool)> = scan2
        .frames
        .iter()
        .map(|f| (f.start_offset, f.end_offset, f.has_eoi, f.is_truncated))
        .collect();
    assert_eq!(
        spans2,
        vec![
            (0, 28, true, false),
            (28, 33, false, true),
            (33, 61, true, false),
        ],
        "complete frame at 33..61 swallowed under cut after high length byte"
    );

    let duration_ms = start.elapsed().as_millis().max(1);
    let passed = spans1.len() == 3 && spans2.len() == 3;
    let (verdict, exit_code) = if passed {
        ("pass", 0)
    } else {
        ("fail", 1)
    };
    let expected =
        r#"{"cut_after_marker_code_spans_3":true,"cut_after_high_length_byte_spans_3":true}"#;
    let observed = format!(
        r#"{{"cut_after_marker_code_spans_3":{},"cut_after_high_length_byte_spans_3":{}}}"#,
        spans1.len() == 3,
        spans2.len() == 3
    );
    emit_caplog(
        "gauntlet_cut_headers",
        verdict,
        exit_code,
        expected,
        &observed,
        duration_ms,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 17: Nested SOI inside ECS (Kills M3)
// ---------------------------------------------------------------------------

#[test]
fn test_gauntlet_nested_soi() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let limits = MjpegLimits::default();

    // Frame 1: SOI + SOF0(8, 8) + SOS1 + [0x11, 0x22] (truncated inside ECS, no EOI)
    let mut f = vec![0xFF, 0xD8];
    f.extend(helper_sof0(8, 8)); // 11 bytes
    f.extend(helper_sos1()); // 10 bytes
    f.extend_from_slice(&[0x11, 0x22]); // 2 bytes -> 25 bytes total
    // Frame 2 starts immediately with SOI
    let g = helper_frame(8, 8, &[0x33]); // 28 bytes
    f.extend_from_slice(&g);

    let scan = split_jpeg_stream(&f, &limits, None)?;
    assert_eq!(scan.frames.len(), 2);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 27);
    assert!(!scan.frames[0].has_eoi);
    assert!(scan.frames[0].is_truncated);

    assert_eq!(scan.frames[1].start_offset, 27);
    assert_eq!(scan.frames[1].end_offset, 55);
    assert!(scan.frames[1].has_eoi);
    assert!(!scan.frames[1].is_truncated);

    assert_eq!(
        scan.findings,
        vec![JpegFinding::TruncatedFrame {
            frame_index: 0,
            start_offset: 0,
            end_offset: 27,
        }]
    );

    let duration_ms = start.elapsed().as_millis().max(1);
    let passed = scan.frames.len() == 2
        && scan.frames[0].is_truncated
        && scan.frames[1].has_eoi
        && scan.findings.len() == 1;
    let (verdict, exit_code) = if passed {
        ("pass", 0)
    } else {
        ("fail", 1)
    };
    let expected =
        r#"{"frames":2,"frame_0_truncated":true,"frame_1_has_eoi":true,"findings_count":1}"#;
    let observed = format!(
        r#"{{"frames":{},"frame_0_truncated":{},"frame_1_has_eoi":{},"findings_count":{}}}"#,
        scan.frames.len(),
        scan.frames[0].is_truncated,
        scan.frames[1].has_eoi,
        scan.findings.len()
    );
    emit_caplog(
        "gauntlet_nested_soi",
        verdict,
        exit_code,
        expected,
        &observed,
        duration_ms,
    );
    Ok(())
}

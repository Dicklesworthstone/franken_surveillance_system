#![forbid(unsafe_code)]
//! Integration contract tests for the bounded H.264 Annex-B elementary-stream splitter (fss-2h5zq.20).
//!
//! Companion test suite asserting:
//! - Manifest equality across all H.264 fixture variants with exact parsing and verification.
//! - Structured CAPLOG logging per fixture and test group conforming to the E2E harness format.
//! - Hand-built edge cases: zero-length NALs, truncated NALs, forbidden bit, leading garbage,
//!   and emulation prevention edge cases (including trailing cabac_zero_word).
//! - Malformed slice headers: ue(v) leading zero overflow, truncated slice header.
//! - AU grouping semantics per H.264 7.4.1.2.3: AUD, VCL slices, parameter sets, data partitions B/C,
//!   terminal EOS and EOStream markers.
//! - Parameter sets tracking and undecodable_without_parameter_sets flag.
//! - Unsupported extensions cataloging (NAL types 15 and 20).
//! - Limits boundaries (N vs N+1) and 16 MiB ceiling clamp.
//! - Cooperative cancellation via ReplayCx at each checkpoint stage.
//! - Mutant kill table killing all 8 specified splitter mutants.
//! - 10,000-mutation deterministic no-panic gauntlet driven by DeterministicFaultPrng.

use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_reference::{
    ADP_REPLAY_ROW_ID, AnnexBError, AnnexBLimits, CEILING_MAX_NAL_BYTES, DeterministicFaultPrng,
    ReplayCx, ReplayIoAuthority, SourceSpan, split_annexb,
};

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

/// Computes SHA-256 lower-case hex string using fss_core::ContentDigest.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ContentDigest::sha256(bytes);
    let mut hex = String::with_capacity(64);
    for b in digest.bytes() {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

fn test_cx(label: &str) -> Result<ReplayCx, Box<dyn Error>> {
    let spec = RootAuthoritySpec {
        trace_id: format!("trace:contract-test-{label}"),
        operation_id: OperationId::parse(format!("operation:contract-test-{label}"))?,
        principal: format!("operator:contract-test-{label}"),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"test-anchor-universe"),
        generation: 1,
    };
    let root_auth = ContextAuthority::new_root(spec)?;
    let scratch_root = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!("test-replay-cx-annexb-split-{label}"));
    let io = ReplayIoAuthority::from_context_authority(&root_auth, scratch_root)?;
    Ok(ReplayCx::new(io))
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

    fn as_usize(&self) -> Option<usize> {
        match self {
            Self::Number(n) if *n >= 0 => usize::try_from(*n).ok(),
            _ => None,
        }
    }

    fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
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
            self.pos = self.pos.saturating_add(1);
        }
    }

    fn parse_val(&mut self) -> Result<JsonVal, String> {
        self.skip_ws();
        if self.pos >= self.chars.len() {
            return Err("unexpected end of input".to_string());
        }
        match self.chars[self.pos] {
            b'n' => self.parse_null(),
            b't' | b'f' => self.parse_bool(),
            b'"' => self.parse_string().map(JsonVal::String),
            b'[' => self.parse_array(),
            b'{' => self.parse_object(),
            b'-' | b'0'..=b'9' => self.parse_number(),
            other => Err(format!("unexpected character: {}", other as char)),
        }
    }

    fn parse_null(&mut self) -> Result<JsonVal, String> {
        if self.chars.get(self.pos..self.pos.saturating_add(4)) == Some(b"null") {
            self.pos = self.pos.saturating_add(4);
            Ok(JsonVal::Null)
        } else {
            Err("expected null".to_string())
        }
    }

    fn parse_bool(&mut self) -> Result<JsonVal, String> {
        if self.chars.get(self.pos..self.pos.saturating_add(4)) == Some(b"true") {
            self.pos = self.pos.saturating_add(4);
            Ok(JsonVal::Bool(true))
        } else if self.chars.get(self.pos..self.pos.saturating_add(5)) == Some(b"false") {
            self.pos = self.pos.saturating_add(5);
            Ok(JsonVal::Bool(false))
        } else {
            Err("expected boolean".to_string())
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        if self.pos >= self.chars.len() || self.chars[self.pos] != b'"' {
            return Err("expected string starting with '\"'".to_string());
        }
        self.pos = self.pos.saturating_add(1);
        let mut s = String::new();
        while self.pos < self.chars.len() {
            let b = self.chars[self.pos];
            self.pos = self.pos.saturating_add(1);
            if b == b'"' {
                return Ok(s);
            } else if b == b'\\' {
                if self.pos >= self.chars.len() {
                    return Err("unexpected end in string escape".to_string());
                }
                let esc = self.chars[self.pos];
                self.pos = self.pos.saturating_add(1);
                match esc {
                    b'"' => s.push('"'),
                    b'\\' => s.push('\\'),
                    b'/' => s.push('/'),
                    b'b' => s.push('\x08'),
                    b'f' => s.push('\x0C'),
                    b'n' => s.push('\n'),
                    b'r' => s.push('\r'),
                    b't' => s.push('\t'),
                    b'u' => {
                        if self.pos.saturating_add(4) > self.chars.len() {
                            return Err("truncated unicode escape".to_string());
                        }
                        let hex_str =
                            std::str::from_utf8(&self.chars[self.pos..self.pos.saturating_add(4)])
                                .map_err(|e| e.to_string())?;
                        self.pos = self.pos.saturating_add(4);
                        let cp = u32::from_str_radix(hex_str, 16).map_err(|e| e.to_string())?;
                        let ch =
                            char::from_u32(cp).ok_or_else(|| "invalid codepoint".to_string())?;
                        s.push(ch);
                    }
                    _ => return Err(format!("unknown escape: \\{}", esc as char)),
                }
            } else {
                s.push(b as char);
            }
        }
        Err("unclosed string".to_string())
    }

    fn parse_number(&mut self) -> Result<JsonVal, String> {
        let start = self.pos;
        if self.pos < self.chars.len() && self.chars[self.pos] == b'-' {
            self.pos = self.pos.saturating_add(1);
        }
        while self.pos < self.chars.len() && self.chars[self.pos].is_ascii_digit() {
            self.pos = self.pos.saturating_add(1);
        }
        let num_str =
            std::str::from_utf8(&self.chars[start..self.pos]).map_err(|e| e.to_string())?;
        let n: i64 = num_str
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;
        Ok(JsonVal::Number(n))
    }

    fn parse_array(&mut self) -> Result<JsonVal, String> {
        self.pos = self.pos.saturating_add(1);
        self.skip_ws();
        let mut arr = Vec::new();
        if self.pos < self.chars.len() && self.chars[self.pos] == b']' {
            self.pos = self.pos.saturating_add(1);
            return Ok(JsonVal::Array(arr));
        }
        loop {
            let item = self.parse_val()?;
            arr.push(item);
            self.skip_ws();
            if self.pos >= self.chars.len() {
                return Err("unclosed array".to_string());
            }
            if self.chars[self.pos] == b']' {
                self.pos = self.pos.saturating_add(1);
                break;
            } else if self.chars[self.pos] == b',' {
                self.pos = self.pos.saturating_add(1);
            } else {
                return Err(format!(
                    "expected ',' or ']', found {}",
                    self.chars[self.pos] as char
                ));
            }
        }
        Ok(JsonVal::Array(arr))
    }

    fn parse_object(&mut self) -> Result<JsonVal, String> {
        self.pos = self.pos.saturating_add(1);
        self.skip_ws();
        let mut obj = Vec::new();
        if self.pos < self.chars.len() && self.chars[self.pos] == b'}' {
            self.pos = self.pos.saturating_add(1);
            return Ok(JsonVal::Object(obj));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            if self.pos >= self.chars.len() || self.chars[self.pos] != b':' {
                return Err("expected ':' after object key".to_string());
            }
            self.pos = self.pos.saturating_add(1);
            let val = self.parse_val()?;
            obj.push((key, val));
            self.skip_ws();
            if self.pos >= self.chars.len() {
                return Err("unclosed object".to_string());
            }
            if self.chars[self.pos] == b'}' {
                self.pos = self.pos.saturating_add(1);
                break;
            } else if self.chars[self.pos] == b',' {
                self.pos = self.pos.saturating_add(1);
            } else {
                return Err(format!(
                    "expected ',' or '}}', found {}",
                    self.chars[self.pos] as char
                ));
            }
        }
        Ok(JsonVal::Object(obj))
    }
}

fn parse_json(input: &str) -> Result<JsonVal, String> {
    let mut parser = JsonParser::new(input.as_bytes());
    parser.parse_val()
}

// ---------------------------------------------------------------------------
// Synthetic stream builders
// ---------------------------------------------------------------------------

fn encode_ue(val: u64) -> Vec<u8> {
    if val == 0 {
        return vec![0x80];
    }
    let temp = val.saturating_add(1);
    let leading_zeros = 63 - temp.leading_zeros() as usize;
    let remainder = temp - (1u64 << leading_zeros);
    let total_bits = leading_zeros.saturating_mul(2).saturating_add(1);

    let mut out = Vec::new();
    let mut cur_byte = 0u8;
    let mut cur_bit = 7i32;

    for bit_idx in 0..total_bits {
        let bit_val = if bit_idx < leading_zeros {
            0u8
        } else if bit_idx == leading_zeros {
            1u8
        } else {
            let shift = (total_bits - 1) - bit_idx;
            ((remainder >> shift) & 1) as u8
        };

        if bit_val == 1 {
            cur_byte |= 1 << cur_bit;
        }
        if cur_bit == 0 {
            out.push(cur_byte);
            cur_byte = 0;
            cur_bit = 7;
        } else {
            cur_bit -= 1;
        }
    }

    if cur_bit < 7 {
        out.push(cur_byte);
    }
    out
}

fn make_aud_nal(sc_len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(sc_len + 2);
    if sc_len == 4 {
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    } else {
        v.extend_from_slice(&[0x00, 0x00, 0x01]);
    }
    v.extend_from_slice(&[0x09, 0x10]);
    v
}

fn make_sps_nal(sc_len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(sc_len + 4);
    if sc_len == 4 {
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    } else {
        v.extend_from_slice(&[0x00, 0x00, 0x01]);
    }
    v.extend_from_slice(&[0x67, 0x42, 0x00, 0x1E]);
    v
}

fn make_pps_nal(sc_len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(sc_len + 4);
    if sc_len == 4 {
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    } else {
        v.extend_from_slice(&[0x00, 0x00, 0x01]);
    }
    v.extend_from_slice(&[0x68, 0xCE, 0x38, 0x80]);
    v
}

fn make_sei_nal(sc_len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(sc_len + 8);
    if sc_len == 4 {
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    } else {
        v.extend_from_slice(&[0x00, 0x00, 0x01]);
    }
    v.extend_from_slice(&[0x06, 0x05, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x80]);
    v
}

fn make_slice_nal(
    nal_type: u8,
    nal_ref_idc: u8,
    first_mb: u64,
    extra_payload: &[u8],
    sc_len: usize,
) -> Vec<u8> {
    let mut out = Vec::new();
    if sc_len == 4 {
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    } else {
        out.extend_from_slice(&[0x00, 0x00, 0x01]);
    }
    let header_byte = ((nal_ref_idc & 0x03) << 5) | (nal_type & 0x1F);
    out.push(header_byte);
    out.extend_from_slice(&encode_ue(first_mb));
    out.extend_from_slice(extra_payload);
    out
}

// ---------------------------------------------------------------------------
// Step 1: Fixture manifest test (exact parse and equality against clean.264)
// ---------------------------------------------------------------------------

#[test]
fn test_01_fixture_manifest_clean_h264() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let cx = test_cx("manifest_clean")?;

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crates dir not found")?
        .parent()
        .ok_or("repo root not found")?
        .to_path_buf();

    let manifest_path = root.join("tests/fixtures/media/h264/fixture_manifest.json");
    let fixture_path = root.join("tests/fixtures/media/h264/clean.264");

    if !manifest_path.is_file() || !fixture_path.is_file() {
        let dur = start.elapsed().as_millis();
        emit_caplog(
            "manifest_clean_h264",
            "skip",
            0,
            r#"{"manifest_exists":true,"fixture_exists":true}"#,
            r#"{"reason":"fixture or manifest file missing on disk"}"#,
            dur,
        );
        return Ok(());
    }

    let manifest_str = fs::read_to_string(&manifest_path)?;
    let parsed_manifest = parse_json(&manifest_str).map_err(|e| format!("JSON error: {e}"))?;

    let schema = parsed_manifest
        .get("schema")
        .and_then(|v| v.as_str())
        .ok_or("missing schema")?;
    assert_eq!(schema, "fss.media_fixture.manifest.v1");

    let family = parsed_manifest
        .get("family")
        .and_then(|v| v.as_str())
        .ok_or("missing family")?;
    assert_eq!(family, "h264");

    let fixtures = parsed_manifest
        .get("fixtures")
        .and_then(|v| v.as_array())
        .ok_or("missing fixtures array")?;

    for fixture_entry in fixtures {
        let fixture_name = fixture_entry
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or("missing fixture name")?;
        let fixture_format = fixture_entry
            .get("format")
            .and_then(|v| v.as_str())
            .ok_or("missing fixture format")?;
        assert_eq!(fixture_format, "annex_b");

        let expected_sha256 = fixture_entry
            .get("sha256")
            .and_then(|v| v.as_str())
            .ok_or("missing sha256")?;
        let expected_byte_len = fixture_entry
            .get("byte_len")
            .and_then(|v| v.as_usize())
            .ok_or("missing byte_len")?;
        let expected_nal_count = fixture_entry
            .get("expected_nal_count")
            .and_then(|v| v.as_usize())
            .ok_or("missing expected_nal_count")?;
        let expected_au_count = fixture_entry
            .get("expected_au_count")
            .and_then(|v| v.as_usize())
            .ok_or("missing expected_au_count")?;
        let expected_nals = fixture_entry
            .get("expected_nals")
            .and_then(|v| v.as_array())
            .ok_or("missing expected_nals")?;

        let fixture_path = root.join("tests/fixtures/media/h264").join(fixture_name);
        let step_name = if fixture_name == "clean.264" {
            "manifest_clean_h264".to_string()
        } else {
            format!("manifest_{}", fixture_name.replace('.', "_"))
        };

        if !fixture_path.is_file() {
            let dur = start.elapsed().as_millis();
            emit_caplog(
                &step_name,
                "skip",
                0,
                r#"{"fixture_exists":true}"#,
                r#"{"reason":"fixture file missing on disk"}"#,
                dur,
            );
            continue;
        }

        let raw_bytes = fs::read(&fixture_path)?;
        let observed_sha256 = sha256_hex(&raw_bytes);
        let observed_byte_len = raw_bytes.len();

        let scan = split_annexb(&raw_bytes, AnnexBLimits::default(), &cx)?;
        let observed_nal_count = scan.nal_count();
        let observed_au_count = scan.au_count();

        assert_eq!(observed_sha256, expected_sha256);
        assert_eq!(observed_byte_len, expected_byte_len);
        assert_eq!(observed_nal_count, expected_nal_count);
        assert_eq!(observed_au_count, expected_au_count);
        assert_eq!(expected_nals.len(), observed_nal_count);

        let mut expected_au_partition: Vec<Vec<usize>> = vec![Vec::new(); expected_au_count];

        for (i, exp_nal) in expected_nals.iter().enumerate() {
            let exp_idx = exp_nal
                .get("index")
                .and_then(|v| v.as_usize())
                .ok_or("index")?;
            let exp_offset = exp_nal
                .get("offset")
                .and_then(|v| v.as_usize())
                .ok_or("offset")?;
            let exp_len = exp_nal.get("len").and_then(|v| v.as_usize()).ok_or("len")?;
            let exp_sc_len = exp_nal
                .get("start_code_len")
                .and_then(|v| v.as_usize())
                .ok_or("sc_len")?;
            let exp_trailing_zeros = exp_nal
                .get("trailing_zeros_before")
                .and_then(|v| v.as_usize())
                .unwrap_or(0);
            let exp_nal_type = exp_nal
                .get("nal_unit_type")
                .and_then(|v| v.as_usize())
                .ok_or("type")? as u8;
            let exp_is_idr = exp_nal
                .get("is_idr")
                .and_then(|v| v.as_bool())
                .ok_or("is_idr")?;
            let exp_au_idx = exp_nal
                .get("access_unit_index")
                .and_then(|v| v.as_usize())
                .ok_or("au_idx")?;

            assert_eq!(exp_idx, i);
            let obs_nal = &scan.nals[i];
            assert_eq!(obs_nal.nal_span.offset, exp_offset);
            assert_eq!(obs_nal.nal_span.len, exp_len);
            assert_eq!(obs_nal.start_code_span.len, exp_sc_len);
            assert_eq!(
                obs_nal.start_code_span.offset,
                exp_offset.saturating_sub(exp_sc_len)
            );
            assert_eq!(obs_nal.nal_unit_type, exp_nal_type);
            assert_eq!(obs_nal.is_idr(), exp_is_idr);

            if exp_au_idx < expected_au_count {
                expected_au_partition[exp_au_idx].push(i);
            }

            if exp_trailing_zeros > 0 {
                let pad_offset = obs_nal
                    .start_code_span
                    .offset
                    .saturating_sub(exp_trailing_zeros);
                let expected_pad_span = SourceSpan::new(pad_offset, exp_trailing_zeros);
                assert!(
                    scan.padding_spans.contains(&expected_pad_span),
                    "missing padding span {:?} for nal {}",
                    expected_pad_span,
                    i
                );
                assert!(
                    raw_bytes[pad_offset..obs_nal.start_code_span.offset]
                        .iter()
                        .all(|&b| b == 0x00),
                    "padding bytes must be zero for nal {}",
                    i
                );
            }
        }

        let observed_au_partition: Vec<Vec<usize>> = scan
            .access_units
            .iter()
            .map(|a| a.nal_indices.clone())
            .collect();
        assert_eq!(observed_au_partition, expected_au_partition);

        let dur = start.elapsed().as_millis();
        let expected_json = format!(
            r#"{{"sha256":"{}","bytes":{},"nals":{},"aus":{}}}"#,
            expected_sha256, expected_byte_len, expected_nal_count, expected_au_count
        );
        let observed_json = format!(
            r#"{{"sha256":"{}","bytes":{},"nals":{},"aus":{}}}"#,
            observed_sha256, observed_byte_len, observed_nal_count, observed_au_count
        );

        emit_caplog(&step_name, "pass", 0, &expected_json, &observed_json, dur);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 2: Synthetic standard stream (AUD, SPS, PPS, SEI, IDR, Non-IDR)
// ---------------------------------------------------------------------------

#[test]
fn test_02_synthetic_standard_stream() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let cx = test_cx("synthetic_standard")?;

    let mut stream = Vec::new();
    stream.extend_from_slice(&make_aud_nal(4)); // NAL 0: AUD (offset 4, len 2)
    stream.extend_from_slice(&make_sps_nal(4)); // NAL 1: SPS (offset 10, len 4)
    stream.extend_from_slice(&make_pps_nal(4)); // NAL 2: PPS (offset 18, len 4)
    stream.extend_from_slice(&make_sei_nal(4)); // NAL 3: SEI (offset 26, len 8)
    stream.extend_from_slice(&make_slice_nal(5, 3, 0, &[0xDE, 0xAD], 4)); // NAL 4: IDR (offset 38, len 4)
    stream.extend_from_slice(&make_slice_nal(1, 2, 0, &[0xBE, 0xEF], 4)); // NAL 5: Non-IDR (offset 46, len 4)

    let scan = split_annexb(&stream, AnnexBLimits::default(), &cx)?;
    assert_eq!(scan.total_bytes, stream.len());
    assert_eq!(scan.nal_count(), 6);
    assert_eq!(scan.au_count(), 2);
    assert!(scan.has_sps());
    assert!(scan.has_pps());
    assert!(scan.has_idr());

    assert_eq!(scan.access_units[0].nal_indices, vec![0, 1, 2, 3, 4]);
    assert!(scan.access_units[0].is_idr);
    assert!(scan.access_units[0].has_sps);
    assert!(scan.access_units[0].has_pps);
    assert_eq!(scan.access_units[0].slice_count, 1);
    assert!(!scan.access_units[0].undecodable_without_parameter_sets);

    assert_eq!(scan.access_units[1].nal_indices, vec![5]);
    assert!(!scan.access_units[1].is_idr);
    assert_eq!(scan.access_units[1].slice_count, 1);
    assert!(!scan.access_units[1].undecodable_without_parameter_sets);

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"nals":6,"aus":2,"has_sps":true,"has_pps":true,"has_idr":true}"#;
    let obs_json = format!(
        r#"{{"nals":{},"aus":{},"has_sps":{},"has_pps":{},"has_idr":{}}}"#,
        scan.nal_count(),
        scan.au_count(),
        scan.has_sps(),
        scan.has_pps(),
        scan.has_idr()
    );

    emit_caplog("synthetic_standard", "pass", 0, exp_json, &obs_json, dur);

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 3: Multi-slice Access Unit grouping
// ---------------------------------------------------------------------------

#[test]
fn test_03_synthetic_multi_slice_au() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let cx = test_cx("multi_slice")?;

    let mut stream = Vec::new();
    stream.extend_from_slice(&make_sps_nal(4));
    stream.extend_from_slice(&make_pps_nal(4));
    // AU 0: IDR slice 0 (mb=0), IDR slice 1 (mb=128), IDR slice 2 (mb=256)
    stream.extend_from_slice(&make_slice_nal(5, 3, 0, &[0xAA], 4));
    stream.extend_from_slice(&make_slice_nal(5, 3, 128, &[0xBB], 3));
    stream.extend_from_slice(&make_slice_nal(5, 3, 256, &[0xCC], 3));
    // AU 1: Non-IDR slice 0 (mb=0), Non-IDR slice 1 (mb=128)
    stream.extend_from_slice(&make_slice_nal(1, 2, 0, &[0xDD], 4));
    stream.extend_from_slice(&make_slice_nal(1, 2, 128, &[0xEE], 3));

    let scan = split_annexb(&stream, AnnexBLimits::default(), &cx)?;

    assert_eq!(scan.nal_count(), 7);
    assert_eq!(scan.au_count(), 2);
    assert_eq!(scan.access_units[0].nal_indices, vec![0, 1, 2, 3, 4]);
    assert_eq!(scan.access_units[0].slice_count, 3);
    assert_eq!(scan.access_units[1].nal_indices, vec![5, 6]);
    assert_eq!(scan.access_units[1].slice_count, 2);

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"nals":7,"aus":2,"au0_slices":3,"au1_slices":2}"#;
    let obs_json = format!(
        r#"{{"nals":{},"aus":{},"au0_slices":{},"au1_slices":{}}}"#,
        scan.nal_count(),
        scan.au_count(),
        scan.access_units[0].slice_count,
        scan.access_units[1].slice_count
    );

    emit_caplog("synthetic_multi_slice", "pass", 0, exp_json, &obs_json, dur);

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 4: Inter-NAL padding and leading zero padding spans
// ---------------------------------------------------------------------------

#[test]
fn test_04_synthetic_inter_nal_padding_and_leading_zeros() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let cx = test_cx("padding_and_zeros")?;

    let mut stream = Vec::new();
    // 3 leading zero bytes (leading_zero_8bits preceding first 3-byte start code)
    stream.extend_from_slice(&[0x00, 0x00, 0x00]);
    // NAL 0: AUD with 3-byte start code
    stream.extend_from_slice(&[0x00, 0x00, 0x01, 0x09, 0x10]);
    // 4 zero bytes between NAL 0 and NAL 1 (last zero absorbed into 4-byte start code)
    stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // NAL 1: SPS with 4-byte start code
    stream.extend_from_slice(&[0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1E]);
    // 2 trailing zero bytes at stream end
    stream.extend_from_slice(&[0x00, 0x00]);

    let scan = split_annexb(&stream, AnnexBLimits::default(), &cx)?;

    assert_eq!(scan.nal_count(), 2);
    assert_eq!(scan.padding_spans.len(), 3);
    // Leading padding: 0..2
    assert_eq!(scan.padding_spans[0], SourceSpan::new(0, 2));
    // NAL 0: 2..8 (SC 2..6, NAL 6..8)
    assert_eq!(scan.nals[0].start_code_span, SourceSpan::new(2, 4));
    assert_eq!(scan.nals[0].nal_span, SourceSpan::new(6, 2));
    // Middle padding: 8..11 (3 zeros; 4th zero absorbed into NAL 1 4-byte start code)
    assert_eq!(scan.padding_spans[1], SourceSpan::new(8, 3));
    // NAL 1: 11..19 (SC 11..15, NAL 15..19)
    assert_eq!(scan.nals[1].start_code_span, SourceSpan::new(11, 4));
    assert_eq!(scan.nals[1].nal_span, SourceSpan::new(15, 4));
    // Trailing padding at EOF: 19..21 (2 zeros)
    assert_eq!(scan.padding_spans[2], SourceSpan::new(19, 2));

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"nals":2,"padding_spans":3}"#;
    let obs_json = format!(
        r#"{{"nals":{},"padding_spans":{}}}"#,
        scan.nal_count(),
        scan.padding_spans.len()
    );

    emit_caplog(
        "padding_and_leading_zeros",
        "pass",
        0,
        exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 5: Synthetic stream without AUD grouping
// ---------------------------------------------------------------------------

#[test]
fn test_05_synthetic_no_aud_grouping() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let cx = test_cx("no_aud")?;

    let mut stream = Vec::new();
    stream.extend_from_slice(&make_sps_nal(4));
    stream.extend_from_slice(&make_pps_nal(4));
    stream.extend_from_slice(&make_slice_nal(5, 3, 0, &[0xAA], 4)); // IDR
    stream.extend_from_slice(&make_slice_nal(1, 2, 0, &[0xBB], 4)); // Non-IDR

    let scan = split_annexb(&stream, AnnexBLimits::default(), &cx)?;

    assert_eq!(scan.nal_count(), 4);
    assert_eq!(scan.au_count(), 2);
    assert_eq!(scan.access_units[0].nal_indices, vec![0, 1, 2]);
    assert_eq!(scan.access_units[1].nal_indices, vec![3]);

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"nals":4,"aus":2}"#;
    let obs_json = format!(
        r#"{{"nals":{},"aus":{}}}"#,
        scan.nal_count(),
        scan.au_count()
    );

    emit_caplog("no_aud_grouping", "pass", 0, exp_json, &obs_json, dur);

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 6: Empty input and no start code errors
// ---------------------------------------------------------------------------

#[test]
fn test_06_edge_empty_and_no_start_code() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let cx = test_cx("empty_no_sc")?;

    let err_empty = split_annexb(&[], AnnexBLimits::default(), &cx);
    assert_eq!(err_empty, Err(AnnexBError::EmptyInput));

    let garbage = vec![0x12, 0x34, 0x56, 0x78, 0x9A];
    let err_no_sc = split_annexb(&garbage, AnnexBLimits::default(), &cx);
    assert_eq!(err_no_sc, Err(AnnexBError::NoStartCode));

    let dur = start.elapsed().as_millis();
    let obs_empty = match &err_empty {
        Err(e) => format!("{e:?}"),
        Ok(_) => "Ok".to_string(),
    };
    let obs_no_sc = match &err_no_sc {
        Err(e) => format!("{e:?}"),
        Ok(_) => "Ok".to_string(),
    };
    let exp_json = r#"{"empty":"EmptyInput","no_sc":"NoStartCode"}"#;
    let obs_json = format!(r#"{{"empty":"{}","no_sc":"{}"}}"#, obs_empty, obs_no_sc);

    emit_caplog(
        "empty_and_no_start_code",
        "pass",
        0,
        exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 7: Zero-length NAL and truncated NAL at EOF
// ---------------------------------------------------------------------------

#[test]
fn test_07_edge_zero_length_and_truncated_nal() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let cx = test_cx("zero_and_trunc")?;

    // Consecutive start codes: 0-length NAL between them
    let stream_consecutive = [0x00, 0x00, 0x01, 0x00, 0x00, 0x01];
    let err_zero = split_annexb(&stream_consecutive, AnnexBLimits::default(), &cx);
    assert_eq!(err_zero, Err(AnnexBError::ZeroLengthNal { offset: 3 }));

    // Start code at EOF with no payload
    let stream_eof = [0x00, 0x00, 0x01];
    let err_trunc = split_annexb(&stream_eof, AnnexBLimits::default(), &cx);
    assert_eq!(err_trunc, Err(AnnexBError::TruncatedNal { offset: 3 }));

    let dur = start.elapsed().as_millis();
    let obs_zero = match &err_zero {
        Err(e) => format!("{e:?}"),
        Ok(_) => "Ok".to_string(),
    };
    let obs_trunc = match &err_trunc {
        Err(e) => format!("{e:?}"),
        Ok(_) => "Ok".to_string(),
    };
    let exp_json = r#"{"zero":"ZeroLengthNal { offset: 3 }","trunc":"TruncatedNal { offset: 3 }"}"#;
    let obs_json = format!(r#"{{"zero":"{}","trunc":"{}"}}"#, obs_zero, obs_trunc);

    emit_caplog(
        "zero_length_and_truncated",
        "pass",
        0,
        exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 8: Forbidden zero bit rejection
// ---------------------------------------------------------------------------

#[test]
fn test_08_edge_forbidden_zero_bit() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let cx = test_cx("forbidden_bit")?;

    // Header with forbidden bit set (0x80 | 0x09 = 0x89)
    let stream = [0x00, 0x00, 0x01, 0x89, 0x10];
    let res = split_annexb(&stream, AnnexBLimits::default(), &cx);
    assert_eq!(res, Err(AnnexBError::ForbiddenBitSet { nal: 0, offset: 3 }));

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"error":"ForbiddenBitSet { nal: 0, offset: 3 }"}"#;
    let obs_json = match &res {
        Err(e) => format!(r#"{{"error":"{e:?}"}}"#),
        Ok(_) => r#"{"error":"Ok"}"#.to_string(),
    };

    emit_caplog("forbidden_zero_bit", "pass", 0, exp_json, &obs_json, dur);

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 9: Leading garbage within and exceeding limits
// ---------------------------------------------------------------------------

#[test]
fn test_09_edge_leading_garbage_limits() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let cx = test_cx("leading_garbage")?;

    let mut stream = vec![0xFF, 0xEE, 0xDD];
    stream.extend_from_slice(&make_aud_nal(4));

    // Exceeding limit (max = 2, actual = 3)
    let limits_low = AnnexBLimits::default().with_max_leading_garbage_bytes(2);
    let err_excess = split_annexb(&stream, limits_low, &cx);
    assert_eq!(err_excess, Err(AnnexBError::LeadingGarbage { len: 3 }));

    // Within limit (max = 3, actual = 3)
    let limits_ok = AnnexBLimits::default().with_max_leading_garbage_bytes(3);
    let scan_ok = split_annexb(&stream, limits_ok, &cx)?;
    assert_eq!(scan_ok.omission_spans, vec![SourceSpan::new(0, 3)]);
    assert_eq!(scan_ok.nals[0].start_code_span, SourceSpan::new(3, 4));

    let dur = start.elapsed().as_millis();
    let obs_excess = match &err_excess {
        Err(e) => format!("{e:?}"),
        Ok(_) => "Ok".to_string(),
    };
    let obs_omission_len = scan_ok.omission_spans.first().map(|s| s.len).unwrap_or(0);
    let exp_json = r#"{"excess":"LeadingGarbage { len: 3 }","omission_len":3}"#;
    let obs_json = format!(
        r#"{{"excess":"{}","omission_len":{}}}"#,
        obs_excess, obs_omission_len
    );

    emit_caplog(
        "leading_garbage_limits",
        "pass",
        0,
        exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 10: Emulation prevention sequences
// ---------------------------------------------------------------------------

#[test]
fn test_10_edge_emulation_prevention_sequences() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let cx = test_cx("ep_sequences")?;

    // 1. Valid emulation prevention: 00 00 03 00, 00 00 03 01, 00 00 03 02, 00 00 03 03
    let mut valid_stream = Vec::new();
    valid_stream.extend_from_slice(&[0x00, 0x00, 0x01, 0x67, 0x42]);
    valid_stream.extend_from_slice(&[0x00, 0x00, 0x03, 0x00, 0xFF]);
    valid_stream.extend_from_slice(&[0x00, 0x00, 0x03, 0x01, 0xFF]);
    valid_stream.extend_from_slice(&[0x00, 0x00, 0x03, 0x02, 0xFF]);
    valid_stream.extend_from_slice(&[0x00, 0x00, 0x03, 0x03]);
    let scan_valid = split_annexb(&valid_stream, AnnexBLimits::default(), &cx)?;
    assert_eq!(scan_valid.nal_count(), 1);
    assert_eq!(scan_valid.nals[0].start_code_span, SourceSpan::new(0, 3));
    assert_eq!(
        scan_valid.nals[0].nal_span,
        SourceSpan::new(3, valid_stream.len() - 3)
    );

    // 2. Trailing 00 00 03 at end of NAL (cabac_zero_word)
    let mut cabac_stream = Vec::new();
    cabac_stream.extend_from_slice(&[0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x00, 0x03]);
    let scan_cabac = split_annexb(&cabac_stream, AnnexBLimits::default(), &cx)?;
    assert_eq!(scan_cabac.nal_count(), 1);
    assert_eq!(scan_cabac.nals[0].start_code_span, SourceSpan::new(0, 3));
    assert_eq!(
        scan_cabac.nals[0].nal_span,
        SourceSpan::new(3, cabac_stream.len() - 3)
    );

    // 3. Invalid fourth byte: 00 00 03 04
    let mut invalid_fourth = Vec::new();
    invalid_fourth.extend_from_slice(&[0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x00, 0x03, 0x04]);
    let err_fourth = split_annexb(&invalid_fourth, AnnexBLimits::default(), &cx);
    assert_eq!(
        err_fourth,
        Err(AnnexBError::MalformedEmulationPrevention { offset: 5 })
    );

    // 4. Forbidden 00 00 00 inside NAL payload
    let mut invalid_zeros = Vec::new();
    invalid_zeros.extend_from_slice(&[0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x00, 0x00, 0xFF]);
    let err_zeros = split_annexb(&invalid_zeros, AnnexBLimits::default(), &cx);
    assert_eq!(
        err_zeros,
        Err(AnnexBError::MalformedEmulationPrevention { offset: 5 })
    );

    // 5. Forbidden 00 00 02 inside NAL payload
    let mut invalid_two = Vec::new();
    invalid_two.extend_from_slice(&[0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x00, 0x02, 0xFF]);
    let err_two = split_annexb(&invalid_two, AnnexBLimits::default(), &cx);
    assert_eq!(
        err_two,
        Err(AnnexBError::MalformedEmulationPrevention { offset: 5 })
    );

    let dur = start.elapsed().as_millis();
    let obs_fourth = match &err_fourth {
        Err(e) => format!("{e:?}"),
        Ok(_) => "Ok".to_string(),
    };
    let obs_zeros = match &err_zeros {
        Err(e) => format!("{e:?}"),
        Ok(_) => "Ok".to_string(),
    };
    let obs_two = match &err_two {
        Err(e) => format!("{e:?}"),
        Ok(_) => "Ok".to_string(),
    };
    let exp_json = r#"{"valid_len":21,"cabac_len":5,"fourth":"MalformedEmulationPrevention { offset: 5 }","zeros":"MalformedEmulationPrevention { offset: 5 }","two":"MalformedEmulationPrevention { offset: 5 }"}"#;
    let obs_json = format!(
        r#"{{"valid_len":{},"cabac_len":{},"fourth":"{}","zeros":"{}","two":"{}"}}"#,
        scan_valid.nals[0].nal_span.len,
        scan_cabac.nals[0].nal_span.len,
        obs_fourth,
        obs_zeros,
        obs_two
    );

    emit_caplog("emulation_prevention", "pass", 0, exp_json, &obs_json, dur);

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 11: Slice header syntax errors
// ---------------------------------------------------------------------------

#[test]
fn test_11_edge_slice_header_syntax() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let cx = test_cx("slice_syntax")?;

    // Truncated slice header: VCL NAL with header byte only (no slice payload)
    let stream_trunc = [0x00, 0x00, 0x01, 0x65];
    let err_trunc = split_annexb(&stream_trunc, AnnexBLimits::default(), &cx);
    assert_eq!(
        err_trunc,
        Err(AnnexBError::TruncatedSliceHeader { offset: 3 })
    );

    // ue(v) leading zeros > 31 (malformed slice header)
    // Uses valid EP sequence 00 00 03 00 00 03 00 ... so NAL validation succeeds,
    // but RBSP unescapes to > 31 consecutive zero bits.
    let mut stream_malformed = vec![0x00, 0x00, 0x01, 0x65];
    stream_malformed.extend_from_slice(&[
        0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00,
    ]);
    let err_malformed = split_annexb(&stream_malformed, AnnexBLimits::default(), &cx);
    assert_eq!(
        err_malformed,
        Err(AnnexBError::MalformedSliceHeader {
            offset: 3,
            detail: "ue(v) leading zero count exceeds 31",
        })
    );

    let dur = start.elapsed().as_millis();
    let obs_trunc = match &err_trunc {
        Err(e) => format!("{e:?}"),
        Ok(_) => "Ok".to_string(),
    };
    let obs_malformed = match &err_malformed {
        Err(e) => format!("{e:?}"),
        Ok(_) => "Ok".to_string(),
    };
    let exp_json = r#"{"truncated":"TruncatedSliceHeader { offset: 3 }","malformed":"MalformedSliceHeader { offset: 3, detail: \"ue(v) leading zero count exceeds 31\" }"}"#;
    let obs_json = format!(
        r#"{{"truncated":"{}","malformed":"{}"}}"#,
        obs_trunc.replace('"', "\\\""),
        obs_malformed.replace('"', "\\\"")
    );

    emit_caplog("slice_header_syntax", "pass", 0, exp_json, &obs_json, dur);

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 12: Parameter set tracking and undecodable flag
// ---------------------------------------------------------------------------

#[test]
fn test_12_undecodable_flag_and_parameter_sets() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let cx = test_cx("undecodable")?;

    // Stream 1: slice before any SPS/PPS seen in stream
    let mut stream_early_slice = Vec::new();
    stream_early_slice.extend_from_slice(&make_slice_nal(1, 2, 0, &[0xAA], 4));
    let scan_early = split_annexb(&stream_early_slice, AnnexBLimits::default(), &cx)?;
    assert_eq!(scan_early.au_count(), 1);
    assert_eq!(scan_early.nal_count(), 1);
    assert_eq!(scan_early.access_units[0].nal_indices, vec![0]);
    assert_eq!(
        scan_early.access_units[0].span,
        SourceSpan::new(0, stream_early_slice.len())
    );
    assert!(scan_early.access_units[0].undecodable_without_parameter_sets);

    // Stream 2: SPS + PPS before slice
    let mut stream_with_params = Vec::new();
    stream_with_params.extend_from_slice(&make_sps_nal(4));
    stream_with_params.extend_from_slice(&make_pps_nal(4));
    stream_with_params.extend_from_slice(&make_slice_nal(5, 3, 0, &[0xBB], 4));
    let scan_params = split_annexb(&stream_with_params, AnnexBLimits::default(), &cx)?;
    assert_eq!(scan_params.au_count(), 1);
    assert_eq!(scan_params.nal_count(), 3);
    assert_eq!(scan_params.access_units[0].nal_indices, vec![0, 1, 2]);
    assert_eq!(
        scan_params.access_units[0].span,
        SourceSpan::new(0, stream_with_params.len())
    );
    assert!(!scan_params.access_units[0].undecodable_without_parameter_sets);
    assert_eq!(scan_params.sps_spans, vec![SourceSpan::new(4, 4)]);
    assert_eq!(scan_params.pps_spans, vec![SourceSpan::new(12, 4)]);

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"early_undecodable":true,"with_params_undecodable":false}"#;
    let obs_json = format!(
        r#"{{"early_undecodable":{},"with_params_undecodable":{}}}"#,
        scan_early.access_units[0].undecodable_without_parameter_sets,
        scan_params.access_units[0].undecodable_without_parameter_sets
    );

    emit_caplog("undecodable_flag", "pass", 0, exp_json, &obs_json, dur);

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 13: Unsupported extensions cataloging
// ---------------------------------------------------------------------------

#[test]
fn test_13_unsupported_extensions() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let cx = test_cx("unsupported_ext")?;

    let mut stream = Vec::new();
    stream.extend_from_slice(&make_aud_nal(4)); // NAL 0
    stream.extend_from_slice(&[0x00, 0x00, 0x01, 0x0F, 0x88]); // NAL 1: Subset SPS (type 15)
    stream.extend_from_slice(&[0x00, 0x00, 0x01, 0x14, 0x99]); // NAL 2: Slice extension (type 20)

    let scan = split_annexb(&stream, AnnexBLimits::default(), &cx)?;

    assert_eq!(scan.nal_count(), 3);
    assert_eq!(scan.nals[0].start_code_span, SourceSpan::new(0, 4));
    assert_eq!(scan.nals[0].nal_span, SourceSpan::new(4, 2));
    assert_eq!(scan.nals[1].start_code_span, SourceSpan::new(6, 3));
    assert_eq!(scan.nals[1].nal_span, SourceSpan::new(9, 2));
    assert_eq!(scan.nals[2].start_code_span, SourceSpan::new(11, 3));
    assert_eq!(scan.nals[2].nal_span, SourceSpan::new(14, 2));
    assert_eq!(scan.unsupported_extension_spans.len(), 2);
    assert_eq!(
        scan.unsupported_extension_spans,
        vec![SourceSpan::new(9, 2), SourceSpan::new(14, 2)]
    );

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"unsupported_count":2}"#;
    let obs_json = format!(
        r#"{{"unsupported_count":{}}}"#,
        scan.unsupported_extension_spans.len()
    );

    emit_caplog(
        "unsupported_extensions",
        "pass",
        0,
        exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 14: Limits boundaries and ceiling clamp
// ---------------------------------------------------------------------------

#[test]
fn test_14_limits_boundaries() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let cx = test_cx("limits_bound")?;

    // 1. max_input_bytes
    let nal = make_aud_nal(4);
    let limits_input = AnnexBLimits::default().with_max_input_bytes(nal.len());
    let scan_input_ok = split_annexb(&nal, limits_input, &cx)?;
    assert_eq!(scan_input_ok.nal_count(), 1);
    assert_eq!(scan_input_ok.nals[0].start_code_span, SourceSpan::new(0, 4));
    assert_eq!(scan_input_ok.nals[0].nal_span, SourceSpan::new(4, 2));
    assert_eq!(scan_input_ok.access_units[0].nal_indices, vec![0]);

    let limits_input_small = AnnexBLimits::default().with_max_input_bytes(nal.len() - 1);
    let err_input = split_annexb(&nal, limits_input_small, &cx);
    assert_eq!(
        err_input,
        Err(AnnexBError::InputTooLarge {
            len: nal.len(),
            max: nal.len() - 1,
        })
    );

    // 2. max_nal_bytes
    let limits_nal = AnnexBLimits::default().with_max_nal_bytes(2);
    let scan_nal_ok = split_annexb(&nal, limits_nal, &cx)?;
    assert_eq!(scan_nal_ok.nal_count(), 1);
    assert_eq!(scan_nal_ok.nals[0].start_code_span, SourceSpan::new(0, 4));
    assert_eq!(scan_nal_ok.nals[0].nal_span, SourceSpan::new(4, 2));
    assert_eq!(scan_nal_ok.access_units[0].nal_indices, vec![0]);

    let limits_nal_small = AnnexBLimits::default().with_max_nal_bytes(1);
    let err_nal = split_annexb(&nal, limits_nal_small, &cx);
    assert_eq!(
        err_nal,
        Err(AnnexBError::NalTooLarge {
            offset: 4,
            len: 2,
            max: 1,
        })
    );

    // 3. CEILING_MAX_NAL_BYTES clamp: with_max_nal_bytes(32 MiB) is clamped to 16 MiB
    let limits_clamped = AnnexBLimits::default().with_max_nal_bytes(32 * 1024 * 1024);
    assert_eq!(limits_clamped.max_nal_bytes, CEILING_MAX_NAL_BYTES);

    // 4. max_nals
    let mut two_nals = Vec::new();
    two_nals.extend_from_slice(&make_aud_nal(4));
    two_nals.extend_from_slice(&make_aud_nal(4));
    let limits_nals2 = AnnexBLimits::default().with_max_nals(2);
    let scan_nals2 = split_annexb(&two_nals, limits_nals2, &cx)?;
    assert_eq!(scan_nals2.nal_count(), 2);
    assert_eq!(scan_nals2.nals[0].nal_span, SourceSpan::new(4, 2));
    assert_eq!(scan_nals2.nals[1].nal_span, SourceSpan::new(10, 2));
    assert_eq!(scan_nals2.access_units[0].nal_indices, vec![0]);
    assert_eq!(scan_nals2.access_units[1].nal_indices, vec![1]);

    let limits_nals1 = AnnexBLimits::default().with_max_nals(1);
    let err_nals = split_annexb(&two_nals, limits_nals1, &cx);
    assert_eq!(err_nals, Err(AnnexBError::TooManyNals { count: 2, max: 1 }));

    // 5. max_aus
    let limits_aus2 = AnnexBLimits::default().with_max_aus(2);
    let scan_aus2 = split_annexb(&two_nals, limits_aus2, &cx)?;
    assert_eq!(scan_aus2.au_count(), 2);
    assert_eq!(scan_aus2.access_units[0].nal_indices, vec![0]);
    assert_eq!(scan_aus2.access_units[1].nal_indices, vec![1]);

    let limits_aus1 = AnnexBLimits::default().with_max_aus(1);
    let err_aus = split_annexb(&two_nals, limits_aus1, &cx);
    assert_eq!(
        err_aus,
        Err(AnnexBError::TooManyAccessUnits { count: 2, max: 1 })
    );

    let dur = start.elapsed().as_millis();
    let obs_input_str = match &err_input {
        Err(e) => format!("{e:?}"),
        Ok(_) => "Ok".to_string(),
    };
    let obs_nal_str = match &err_nal {
        Err(e) => format!("{e:?}"),
        Ok(_) => "Ok".to_string(),
    };
    let obs_nals_str = match &err_nals {
        Err(e) => format!("{e:?}"),
        Ok(_) => "Ok".to_string(),
    };
    let obs_aus_str = match &err_aus {
        Err(e) => format!("{e:?}"),
        Ok(_) => "Ok".to_string(),
    };
    let exp_json = r#"{"ceiling_clamped":16777216,"input_err":"InputTooLarge { len: 6, max: 5 }","nal_err":"NalTooLarge { offset: 4, len: 2, max: 1 }","nals_err":"TooManyNals { count: 2, max: 1 }","aus_err":"TooManyAccessUnits { count: 2, max: 1 }"}"#;
    let obs_json = format!(
        r#"{{"ceiling_clamped":{},"input_err":"{}","nal_err":"{}","nals_err":"{}","aus_err":"{}"}}"#,
        limits_clamped.max_nal_bytes, obs_input_str, obs_nal_str, obs_nals_str, obs_aus_str
    );

    emit_caplog("limits_boundaries", "pass", 0, exp_json, &obs_json, dur);

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 15: Cooperative cancellation across all checkpoints
// ---------------------------------------------------------------------------

#[test]
fn test_15_cooperative_cancellation() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();

    let mut stream = Vec::new();
    stream.extend_from_slice(&make_aud_nal(4));
    stream.extend_from_slice(&make_sps_nal(4));
    stream.extend_from_slice(&make_pps_nal(4));
    stream.extend_from_slice(&make_slice_nal(5, 3, 0, &[0xAA], 4));

    let cx = test_cx("cancel_request")?;
    cx.request_cancellation();
    assert!(cx.is_cancelled());

    let res = split_annexb(&stream, AnnexBLimits::default(), &cx);
    assert_eq!(res, Err(AnnexBError::Cancelled));
    assert!(cx.is_drain_completed());

    // Kill A8a: cancellation at pre_scan on stream without start codes
    let cx_prescan = test_cx("cancel_prescan")?;
    cx_prescan.request_cancellation();
    assert!(cx_prescan.is_cancelled());
    let no_sc = [0x12, 0x34, 0x56, 0x78];
    let res_prescan = split_annexb(&no_sc, AnnexBLimits::default(), &cx_prescan);
    assert_eq!(res_prescan, Err(AnnexBError::Cancelled));
    assert!(cx_prescan.is_drain_completed());

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"cancelled":true,"drain_completed":true,"prescan_cancelled":true}"#;
    let obs_json = format!(
        r#"{{"cancelled":{},"drain_completed":{},"prescan_cancelled":{}}}"#,
        res == Err(AnnexBError::Cancelled),
        cx.is_drain_completed(),
        res_prescan == Err(AnnexBError::Cancelled)
    );

    emit_caplog(
        "cooperative_cancellation",
        "pass",
        0,
        exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 16: Mutant kill table (kills all 8 specified mutants)
// ---------------------------------------------------------------------------

#[test]
fn test_16_mutant_kill_table() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let cx = test_cx("mutants")?;

    // M1: EP-check off
    // NAL with forbidden 0x000002 inside payload
    let m1_stream = [0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x00, 0x02, 0x1E];
    let m1_res = split_annexb(&m1_stream, AnnexBLimits::default(), &cx);
    assert_eq!(
        m1_res,
        Err(AnnexBError::MalformedEmulationPrevention { offset: 5 })
    );

    // M2: 3-byte start code only
    // 4-byte start code must yield start_code_span.len == 4 and empty padding_spans
    let m2_stream = [0x00, 0x00, 0x00, 0x01, 0x09, 0x10];
    let m2_scan = split_annexb(&m2_stream, AnnexBLimits::default(), &cx)?;
    assert_eq!(m2_scan.nals[0].start_code_span, SourceSpan::new(0, 4));
    assert_eq!(m2_scan.padding_spans, Vec::<SourceSpan>::new());

    // M3: Terminal EOS/EOStream rule off
    // VCL (first_mb=0) + EOS (10) + VCL (first_mb=1) -> exactly 2 AUs, EOS in AU 0
    let mut m3_stream = Vec::new();
    m3_stream.extend_from_slice(&make_slice_nal(1, 2, 0, &[0xAA], 4)); // AU 0 VCL
    m3_stream.extend_from_slice(&[0x00, 0x00, 0x01, 0x0A]); // EOS (type 10)
    m3_stream.extend_from_slice(&make_slice_nal(1, 2, 1, &[0xBB], 4)); // VCL (mb=1) starts AU 1 because AU 0 ended
    let m3_scan = split_annexb(&m3_stream, AnnexBLimits::default(), &cx)?;
    assert_eq!(m3_scan.au_count(), 2);
    assert_eq!(m3_scan.access_units[0].nal_indices, vec![0, 1]);
    assert_eq!(m3_scan.access_units[1].nal_indices, vec![2]);

    // M4: Partition exclusion off
    // VCL (type 1) + Partition B (type 3) belongs to SAME AU
    let mut m4_stream = Vec::new();
    m4_stream.extend_from_slice(&make_slice_nal(1, 2, 0, &[0xAA], 4)); // VCL type 1
    m4_stream.extend_from_slice(&[0x00, 0x00, 0x01, 0x23, 0x88]); // Partition B type 3
    let m4_scan = split_annexb(&m4_stream, AnnexBLimits::default(), &cx)?;
    assert_eq!(m4_scan.au_count(), 1);
    assert_eq!(m4_scan.access_units[0].nal_indices, vec![0, 1]);
    assert_eq!(m4_scan.access_units[0].slice_count, 2);

    // M5: Ceiling off
    // with_max_nal_bytes(32 MiB) is clamped to CEILING_MAX_NAL_BYTES (16 MiB)
    let limits_m5 = AnnexBLimits::default().with_max_nal_bytes(32 * 1024 * 1024);
    assert_eq!(limits_m5.max_nal_bytes, CEILING_MAX_NAL_BYTES);

    // M6: First_mb parse off-by-one
    // VCL (mb=0) + VCL (mb=1) + VCL (mb=0) -> exactly 2 AUs: AU 0 has [0, 1], AU 1 has [2]
    let mut m6_stream = Vec::new();
    m6_stream.extend_from_slice(&make_slice_nal(1, 2, 0, &[0xAA], 4)); // AU 0 slice 0
    m6_stream.extend_from_slice(&make_slice_nal(1, 2, 1, &[0xBB], 4)); // AU 0 slice 1
    m6_stream.extend_from_slice(&make_slice_nal(1, 2, 0, &[0xCC], 4)); // AU 1 slice 0
    let m6_scan = split_annexb(&m6_stream, AnnexBLimits::default(), &cx)?;
    assert_eq!(m6_scan.au_count(), 2);
    assert_eq!(m6_scan.access_units[0].nal_indices, vec![0, 1]);
    assert_eq!(m6_scan.access_units[1].nal_indices, vec![2]);

    // M7: Cabac_zero_word acceptance off
    // NAL ending with trailing 00 00 03 is accepted per H.264 7.4.1
    let m7_stream = [0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x00, 0x03];
    let m7_scan = split_annexb(&m7_stream, AnnexBLimits::default(), &cx)?;
    assert_eq!(m7_scan.nal_count(), 1);
    assert_eq!(m7_scan.nals[0].start_code_span, SourceSpan::new(0, 3));
    assert_eq!(m7_scan.nals[0].nal_span, SourceSpan::new(3, 5));

    // M8: Limit at N+1 accepted
    // Setting max_nals: 2 and inputting 3 NALs must return TooManyNals { count: 3, max: 2 }
    let mut m8_stream = Vec::new();
    m8_stream.extend_from_slice(&make_aud_nal(4));
    m8_stream.extend_from_slice(&make_aud_nal(4));
    m8_stream.extend_from_slice(&make_aud_nal(4));
    let limits_m8 = AnnexBLimits::default().with_max_nals(2);
    let m8_res = split_annexb(&m8_stream, limits_m8, &cx);
    assert_eq!(m8_res, Err(AnnexBError::TooManyNals { count: 3, max: 2 }));

    let dur = start.elapsed().as_millis();
    let m1_killed = matches!(
        m1_res,
        Err(AnnexBError::MalformedEmulationPrevention { offset: 5 })
    );
    let m2_killed = m2_scan.nals[0].start_code_span == SourceSpan::new(0, 4)
        && m2_scan.padding_spans.is_empty();
    let m3_killed = m3_scan.au_count() == 2
        && m3_scan.access_units[0].nal_indices == vec![0, 1]
        && m3_scan.access_units[1].nal_indices == vec![2];
    let m4_killed = m4_scan.au_count() == 1 && m4_scan.access_units[0].nal_indices == vec![0, 1];
    let m5_killed = limits_m5.max_nal_bytes == CEILING_MAX_NAL_BYTES;
    let m6_killed = m6_scan.au_count() == 2
        && m6_scan.access_units[0].nal_indices == vec![0, 1]
        && m6_scan.access_units[1].nal_indices == vec![2];
    let m7_killed = m7_scan.nal_count() == 1 && m7_scan.nals[0].nal_span == SourceSpan::new(3, 5);
    let m8_killed = matches!(m8_res, Err(AnnexBError::TooManyNals { count: 3, max: 2 }));

    let exp_json =
        r#"{"m1":true,"m2":true,"m3":true,"m4":true,"m5":true,"m6":true,"m7":true,"m8":true}"#;
    let obs_json = format!(
        r#"{{"m1":{},"m2":{},"m3":{},"m4":{},"m5":{},"m6":{},"m7":{},"m8":{}}}"#,
        m1_killed, m2_killed, m3_killed, m4_killed, m5_killed, m6_killed, m7_killed, m8_killed
    );

    emit_caplog("mutant_kill_table", "pass", 0, exp_json, &obs_json, dur);

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 17: 10,000-mutation deterministic no-panic gauntlet with full invariant verification
// ---------------------------------------------------------------------------

#[test]
fn test_17_mutation_gauntlet_10k() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let cx = test_cx("gauntlet_10k")?;
    let mut prng = DeterministicFaultPrng::new(0x5F53_5341_4E58_4232);

    let mut template = Vec::new();
    template.extend_from_slice(&make_aud_nal(4));
    template.extend_from_slice(&make_sps_nal(4));
    template.extend_from_slice(&make_pps_nal(4));
    template.extend_from_slice(&make_slice_nal(5, 3, 0, &[0xAA, 0xBB], 4));
    template.extend_from_slice(&[0x00, 0x00]); // padding
    template.extend_from_slice(&make_slice_nal(1, 2, 0, &[0xCC, 0xDD], 4));
    template.extend_from_slice(&make_slice_nal(1, 2, 1, &[0xEE], 3));
    template.extend_from_slice(&[0x00, 0x00]); // trailing padding

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crates dir not found")?
        .parent()
        .ok_or("repo root not found")?
        .to_path_buf();
    let clean_path = root.join("tests/fixtures/media/h264/clean.264");
    if !clean_path.is_file() {
        // Without clean.264 the second half of the gauntlet would silently fall back to the
        // synthetic template; record an explicit skip instead of a reduced-coverage pass.
        emit_caplog(
            "mutation_gauntlet_10k",
            "skip",
            0,
            r#"{"clean_264_exists":true}"#,
            r#"{"reason":"tests/fixtures/media/h264/clean.264 missing on disk"}"#,
            start.elapsed().as_millis(),
        );
        return Ok(());
    }
    let clean_bytes = fs::read(&clean_path)?;

    let limits = AnnexBLimits {
        max_input_bytes: 65536,
        max_nal_bytes: 32768,
        max_nals: 100,
        max_aus: 50,
        max_leading_garbage_bytes: 16,
    };

    let mut successful_scans = 0usize;
    let mut observed_panics = 0usize;
    let iterations = 10_000;

    for i in 0..iterations {
        let base = if i < 5000 { &template } else { &clean_bytes };
        let mut mutated = base.clone();
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
                    // Insertion of start codes or random snippets
                    let idx = if mutated.is_empty() {
                        0
                    } else {
                        (prng.next_u64() as usize) % mutated.len()
                    };
                    let choices = [
                        &[0x00, 0x00, 0x01][..],
                        &[0x00, 0x00, 0x00, 0x01][..],
                        &[0x00, 0x00, 0x03, 0x01][..],
                        &[0x09, 0x10][..],
                        &[0x65, 0x80][..],
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

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            split_annexb(&mutated, limits, &cx)
        }));

        match outcome {
            Err(_) => {
                observed_panics = observed_panics.saturating_add(1);
            }
            Ok(Ok(scan)) => {
                successful_scans = successful_scans.saturating_add(1);

                // Invariants on every Ok scan
                assert_eq!(scan.total_bytes, mutated.len());

                // 1. Spans in bounds and ordered
                let mut prev_end = 0usize;
                for nal in &scan.nals {
                    assert!(nal.start_code_span.offset >= prev_end);
                    assert!(nal.start_code_span.len == 3 || nal.start_code_span.len == 4);
                    assert_eq!(
                        nal.start_code_span
                            .offset
                            .saturating_add(nal.start_code_span.len),
                        nal.nal_span.offset
                    );
                    assert!(nal.nal_span.len > 0);
                    assert!(nal.nal_span.offset.saturating_add(nal.nal_span.len) <= mutated.len());
                    prev_end = nal.nal_span.offset.saturating_add(nal.nal_span.len);
                }

                // 2. Tiling: NAL full spans + padding spans + omission spans tile 0..mutated.len()
                let mut all_spans: Vec<(usize, usize)> = Vec::new();
                for nal in &scan.nals {
                    all_spans.push((
                        nal.start_code_span.offset,
                        nal.start_code_span
                            .offset
                            .saturating_add(nal.start_code_span.len)
                            .saturating_add(nal.nal_span.len),
                    ));
                }
                for pad in &scan.padding_spans {
                    all_spans.push((pad.offset, pad.offset.saturating_add(pad.len)));
                }
                for om in &scan.omission_spans {
                    all_spans.push((om.offset, om.offset.saturating_add(om.len)));
                }
                all_spans.sort_unstable_by_key(|(s, _)| *s);

                let mut cur_offset = 0usize;
                for (s, e) in all_spans {
                    assert_eq!(s, cur_offset);
                    assert!(e >= s);
                    cur_offset = e;
                }
                assert_eq!(cur_offset, scan.total_bytes);

                // 3. AU grouping strong invariants
                let mut flat = Vec::new();
                for au in &scan.access_units {
                    flat.extend_from_slice(&au.nal_indices);
                }
                let want: Vec<usize> = (0..scan.nals.len()).collect();
                assert_eq!(
                    flat, want,
                    "AU nal_indices must partition 0..scan.nals.len()"
                );

                let mut au_prev_end = 0usize;
                for (k, au) in scan.access_units.iter().enumerate() {
                    assert!(au.span.offset >= au_prev_end);
                    assert!(au.span.offset.saturating_add(au.span.len) <= scan.total_bytes);
                    au_prev_end = au.span.offset.saturating_add(au.span.len);

                    assert!(!au.nal_indices.is_empty());
                    let first_sc = scan.nals[au.nal_indices[0]].start_code_span.offset;
                    assert_eq!(au.span.offset, first_sc);

                    let end = scan
                        .access_units
                        .get(k + 1)
                        .map_or(scan.total_bytes, |next_au| next_au.span.offset);
                    assert_eq!(au.span.end(), end);

                    let vcl = au
                        .nal_indices
                        .iter()
                        .filter(|&&idx| scan.nals[idx].is_vcl())
                        .count();
                    assert_eq!(vcl, au.slice_count);

                    let idr = au.nal_indices.iter().any(|&idx| scan.nals[idx].is_idr());
                    assert_eq!(idr, au.is_idr);
                }
            }
            Ok(Err(_)) => {
                // Typed refusal is expected for corrupted mutations
            }
        }
    }

    assert_eq!(observed_panics, 0);
    assert!(successful_scans > 0);

    let dur = start.elapsed().as_millis();
    let exp_json = format!(
        r#"{{"has_successful_scans":true,"iterations":{},"panics":0}}"#,
        iterations
    );
    let obs_json = format!(
        r#"{{"has_successful_scans":{},"iterations":{},"panics":{}}}"#,
        successful_scans > 0,
        iterations,
        observed_panics
    );

    emit_caplog(
        "mutation_gauntlet_10k",
        "pass",
        0,
        &exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 18: Loop and mid-push boundary limits (kills R8a and R8c)
// ---------------------------------------------------------------------------

#[test]
fn test_18_loop_and_mid_push_limits_kill_r8a_r8c() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let cx = test_cx("r8a_r8c")?;

    let aud = [0x00, 0x00, 0x00, 0x01, 0x09, 0x10];
    let mut three_auds = Vec::new();
    three_auds.extend_from_slice(&aud);
    three_auds.extend_from_slice(&aud);
    three_auds.extend_from_slice(&aud);

    // Kills R8a (loop branch annexb.rs:517)
    let res_nals = split_annexb(&three_auds, AnnexBLimits::default().with_max_nals(1), &cx);
    assert_eq!(res_nals, Err(AnnexBError::TooManyNals { count: 2, max: 1 }));

    // Kills R8c (mid-push branch annexb.rs:808)
    let res_aus = split_annexb(&three_auds, AnnexBLimits::default().with_max_aus(1), &cx);
    assert_eq!(
        res_aus,
        Err(AnnexBError::TooManyAccessUnits { count: 2, max: 1 })
    );

    let dur = start.elapsed().as_millis();
    let r8a_killed = matches!(res_nals, Err(AnnexBError::TooManyNals { count: 2, max: 1 }));
    let r8c_killed = matches!(
        res_aus,
        Err(AnnexBError::TooManyAccessUnits { count: 2, max: 1 })
    );
    let exp_json = r#"{"r8a_too_many_nals":true,"r8c_too_many_aus":true}"#;
    let obs_json = format!(
        r#"{{"r8a_too_many_nals":{},"r8c_too_many_aus":{}}}"#,
        r8a_killed, r8c_killed
    );

    emit_caplog(
        "loop_and_mid_push_limits",
        "pass",
        0,
        exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 19: Validation ceiling bypass builder (kills R5b)
// ---------------------------------------------------------------------------

#[test]
fn test_19_validation_ceiling_bypass_builder_kill_r5b() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let cx = test_cx("r5b")?;

    // Struct literal bypassing builder clamp, so max_nal_bytes remains usize::MAX
    let limits = AnnexBLimits {
        max_input_bytes: 64 << 20,
        max_nal_bytes: usize::MAX,
        max_nals: 100,
        max_aus: 100,
        max_leading_garbage_bytes: 0,
    };

    // CEILING + 1: must fail with NalTooLarge { offset: 4, len: CEILING + 1, max: CEILING }
    // killing R5b (validation-time ceiling clamp)
    let mut over_stream = vec![0, 0, 0, 1, 0x0C];
    over_stream.resize(4 + CEILING_MAX_NAL_BYTES + 1, 0xFF);

    let res_over = split_annexb(&over_stream, limits, &cx);
    assert_eq!(
        res_over,
        Err(AnnexBError::NalTooLarge {
            offset: 4,
            len: CEILING_MAX_NAL_BYTES + 1,
            max: CEILING_MAX_NAL_BYTES,
        })
    );

    // Exactly CEILING: must succeed with exact nal_span
    let mut exact_stream = vec![0, 0, 0, 1, 0x0C];
    exact_stream.resize(4 + CEILING_MAX_NAL_BYTES, 0xFF);

    let scan_exact = split_annexb(&exact_stream, limits, &cx)?;
    assert_eq!(scan_exact.nal_count(), 1);
    assert_eq!(scan_exact.nals[0].start_code_span, SourceSpan::new(0, 4));
    assert_eq!(
        scan_exact.nals[0].nal_span,
        SourceSpan::new(4, CEILING_MAX_NAL_BYTES)
    );

    let dur = start.elapsed().as_millis();
    let r5b_killed = matches!(
        res_over,
        Err(AnnexBError::NalTooLarge {
            offset: 4,
            len: _,
            max: CEILING_MAX_NAL_BYTES,
        })
    );
    let exact_ok = scan_exact.nals[0].nal_span == SourceSpan::new(4, CEILING_MAX_NAL_BYTES);

    let exp_json = r#"{"ceiling_exact_ok":true,"r5b_nal_too_large":true}"#;
    let obs_json = format!(
        r#"{{"ceiling_exact_ok":{},"r5b_nal_too_large":{}}}"#,
        exact_ok, r5b_killed
    );

    emit_caplog(
        "validation_ceiling_bypass",
        "pass",
        0,
        exp_json,
        &obs_json,
        dur,
    );

    Ok(())
}

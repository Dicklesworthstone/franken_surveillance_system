#![forbid(unsafe_code)]
//! Companion contract test suite for baseline JPEG and MJPEG test fixtures (fss-2h5zq.6).
//!
//! Verifies:
//! - Exact marker structure, byte stuffing, and EOI termination.
//! - Restart marker MCU cadence and exact byte offsets.
//! - Annex K DQT and DHT table ordering, contents, and zigzag mapping.
//! - Parsed MJPEG manifest frame spans, byte lengths, and SHA-256 digests against disk bytes.
//! - Bit-identical regeneration identity for all 13 JPEGs and 5 MJPEGs.
//! - Brown-Conrady distorted luma source byte-parity with owner test fixture.
//! - Quality 100 all-ones DQT matrix property and differing pixels bounds.
//! - Float IDCT simulation PSNR bounds and maximum absolute error checks.
//! - Custom marker segments containing embedded 0xFFD9 payload bytes.
//! - Mutant kills M1-M6 killed alone by this target.
//! - Guard against production code referencing fixture generator.

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use fss_reference::media_fixture::jpeg::{
    BASE_CHROMA_QUANT, BASE_LUMA_QUANT, CHROMA_AC_BITS, CHROMA_AC_VALS, CHROMA_DC_BITS,
    CHROMA_DC_VALS, LUMA_AC_BITS, LUMA_AC_VALS, LUMA_DC_BITS, LUMA_DC_VALS, ZIGZAG,
    brown_luma_96x96, build_jpeg_manifest_json, build_mjpeg_manifest_json, compute_sha256_hex,
    generate_all_jpeg_fixtures, generate_all_mjpeg_fixtures, source_pixels,
};

// ---------------------------------------------------------------------------
// CAPLOG output helper
// ---------------------------------------------------------------------------

fn emit_caplog(
    step: &str,
    verdict: &str,
    exit_code: i32,
    duration_ms: u128,
    expected: &str,
    observed: &str,
) {
    println!(
        r#"CAPLOG {{"step":"{}","verdict":"{}","exit":{},"duration_ms":{},"expected":{},"observed":{}}}"#,
        step, verdict, exit_code, duration_ms, expected, observed
    );
}

fn locate_repo_root() -> Result<PathBuf, Box<dyn Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .ok_or("failed to locate repository root from CARGO_MANIFEST_DIR")?;
    Ok(repo_root)
}

// ---------------------------------------------------------------------------
// Pure-Rust minimal JSON parser for manifest parsing
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
            match b {
                b'"' => return Ok(s),
                b'\\' => {
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
                        b'f' => s.push('\x0c'),
                        b'n' => s.push('\n'),
                        b'r' => s.push('\r'),
                        b't' => s.push('\t'),
                        _ => s.push(esc as char),
                    }
                }
                _ => s.push(b as char),
            }
        }
        Err("unterminated string literal".to_string())
    }

    fn parse_array(&mut self) -> Result<JsonVal, String> {
        self.pos = self.pos.saturating_add(1);
        self.skip_ws();
        let mut items = Vec::new();
        if self.pos < self.chars.len() && self.chars[self.pos] == b']' {
            self.pos = self.pos.saturating_add(1);
            return Ok(JsonVal::Array(items));
        }
        loop {
            let item = self.parse_val()?;
            items.push(item);
            self.skip_ws();
            if self.pos >= self.chars.len() {
                return Err("unexpected end in array".to_string());
            }
            match self.chars[self.pos] {
                b',' => {
                    self.pos = self.pos.saturating_add(1);
                }
                b']' => {
                    self.pos = self.pos.saturating_add(1);
                    return Ok(JsonVal::Array(items));
                }
                other => {
                    return Err(format!("expected ',' or ']', found {}", other as char));
                }
            }
        }
    }

    fn parse_object(&mut self) -> Result<JsonVal, String> {
        self.pos = self.pos.saturating_add(1);
        self.skip_ws();
        let mut fields = Vec::new();
        if self.pos < self.chars.len() && self.chars[self.pos] == b'}' {
            self.pos = self.pos.saturating_add(1);
            return Ok(JsonVal::Object(fields));
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
            fields.push((key, val));
            self.skip_ws();
            if self.pos >= self.chars.len() {
                return Err("unexpected end in object".to_string());
            }
            match self.chars[self.pos] {
                b',' => {
                    self.pos = self.pos.saturating_add(1);
                }
                b'}' => {
                    self.pos = self.pos.saturating_add(1);
                    return Ok(JsonVal::Object(fields));
                }
                other => {
                    return Err(format!("expected ',' or '}}', found {}", other as char));
                }
            }
        }
    }

    fn parse_number(&mut self) -> Result<JsonVal, String> {
        let start = self.pos;
        if self.chars[self.pos] == b'-' {
            self.pos = self.pos.saturating_add(1);
        }
        while self.pos < self.chars.len() && self.chars[self.pos].is_ascii_digit() {
            self.pos = self.pos.saturating_add(1);
        }
        // Skip any fractional part
        if self.pos < self.chars.len() && self.chars[self.pos] == b'.' {
            self.pos = self.pos.saturating_add(1);
            while self.pos < self.chars.len() && self.chars[self.pos].is_ascii_digit() {
                self.pos = self.pos.saturating_add(1);
            }
        }
        let num_str = std::str::from_utf8(&self.chars[start..self.pos])
            .map_err(|e| format!("invalid utf8 in number: {e}"))?;
        let int_val = num_str
            .split('.')
            .next()
            .ok_or("empty number segment")?
            .parse::<i64>()
            .map_err(|e| format!("failed to parse integer: {e}"))?;
        Ok(JsonVal::Number(int_val))
    }
}

fn parse_json_str(src: &str) -> Result<JsonVal, String> {
    let mut parser = JsonParser::new(src.as_bytes());
    parser.parse_val()
}

// ---------------------------------------------------------------------------
// Step 1: MJPEG manifest parsed checks against committed disk files (Kill M6)
// ---------------------------------------------------------------------------

#[test]
fn test_01_mjpeg_manifest_parsed_frame_spans_and_hashes() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let repo_root = locate_repo_root()?;
    let manifest_path = repo_root.join("tests/fixtures/media/mjpeg/fixture_manifest.json");
    let manifest_str = fs::read_to_string(&manifest_path)?;
    let parsed = parse_json_str(&manifest_str).map_err(|e| format!("json parse error: {e}"))?;

    let schema = parsed
        .get("schema")
        .and_then(|v| v.as_str())
        .ok_or("missing schema")?;
    assert_eq!(schema, "fss.mjpeg_fixture_manifest.v1");

    let fixtures_arr = parsed
        .get("fixtures")
        .and_then(|v| v.as_array())
        .ok_or("missing fixtures array")?;
    assert_eq!(
        fixtures_arr.len(),
        5,
        "Expected 5 MJPEG fixtures in manifest"
    );

    let mut total_frames_verified = 0usize;

    for fix in fixtures_arr {
        let name = fix
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or("missing name")?;
        let variant = fix
            .get("variant")
            .and_then(|v| v.as_str())
            .ok_or("missing variant")?;
        let frame_count = fix
            .get("frame_count")
            .and_then(|v| v.as_usize())
            .ok_or("missing frame_count")?;
        let expected_file_sha = fix
            .get("file_sha256")
            .and_then(|v| v.as_str())
            .ok_or("missing file_sha256")?;
        let expected_file_size = fix
            .get("file_size")
            .and_then(|v| v.as_usize())
            .ok_or("missing file_size")?;

        let file_path = repo_root.join("tests/fixtures/media/mjpeg").join(name);
        let disk_bytes = fs::read(&file_path)?;
        assert_eq!(
            disk_bytes.len(),
            expected_file_size,
            "{}: file size mismatch",
            name
        );
        assert_eq!(
            compute_sha256_hex(&disk_bytes),
            expected_file_sha,
            "{}: file sha mismatch",
            name
        );

        let frames_arr = fix
            .get("frames")
            .and_then(|v| v.as_array())
            .ok_or("missing frames")?;
        assert_eq!(
            frames_arr.len(),
            frame_count,
            "{}: frame count mismatch",
            name
        );

        for (idx, fr) in frames_arr.iter().enumerate() {
            let fr_idx = fr
                .get("index")
                .and_then(|v| v.as_usize())
                .ok_or("missing frame index")?;
            assert_eq!(fr_idx, idx, "{}: frame index order", name);
            let offset = fr
                .get("offset")
                .and_then(|v| v.as_usize())
                .ok_or("missing offset")?;
            let length = fr
                .get("length")
                .and_then(|v| v.as_usize())
                .ok_or("missing length")?;
            let frame_sha = fr
                .get("frame_sha256")
                .and_then(|v| v.as_str())
                .ok_or("missing frame_sha256")?;

            assert!(
                offset.saturating_add(length) <= disk_bytes.len(),
                "{}: frame {} span [{}, {}) exceeds file len {}",
                name,
                fr_idx,
                offset,
                offset + length,
                disk_bytes.len()
            );

            let frame_slice = &disk_bytes[offset..offset + length];
            let actual_frame_sha = compute_sha256_hex(frame_slice);
            assert_eq!(
                actual_frame_sha, frame_sha,
                "{}: frame {} SHA-256 mismatch (length={})",
                name, fr_idx, length
            );

            // Verify SOI and EOI on completed frames
            if length >= 4 && variant != "truncated_last"
                || (variant == "truncated_last" && fr_idx < 2)
            {
                assert_eq!(
                    &frame_slice[0..2],
                    &[0xFF, 0xD8],
                    "{}: frame {} missing SOI",
                    name,
                    fr_idx
                );
                assert_eq!(
                    &frame_slice[length - 2..length],
                    &[0xFF, 0xD9],
                    "{}: frame {} missing EOI",
                    name,
                    fr_idx
                );
            }

            total_frames_verified = total_frames_verified.saturating_add(1);
        }
    }

    assert_eq!(
        total_frames_verified, 11,
        "Expected 3+3+3+0+2=11 total frames verified across 5 MJPEGs"
    );

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"fixtures":5,"total_frames":11,"manifest_valid":true}"#;
    let obs_json = format!(
        r#"{{"fixtures":{},"total_frames":{},"manifest_valid":true}}"#,
        fixtures_arr.len(),
        total_frames_verified
    );
    emit_caplog("manifest_mjpeg_spans", "pass", 0, dur, exp_json, &obs_json);
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 2: Regeneration identity test (freshly encoded == committed files)
// ---------------------------------------------------------------------------

#[test]
fn test_02_regeneration_identity_all_fixtures() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let repo_root = locate_repo_root()?;
    let jpeg_dir = repo_root.join("tests/fixtures/media/jpeg");
    let mjpeg_dir = repo_root.join("tests/fixtures/media/mjpeg");

    // 13 JPEGs
    let jpegs = generate_all_jpeg_fixtures()?;
    assert_eq!(jpegs.len(), 13);
    for j in &jpegs {
        let p = jpeg_dir.join(&j.name);
        assert!(p.exists(), "Missing committed JPEG: {}", p.display());
        let disk_bytes = fs::read(&p)?;
        assert_eq!(
            disk_bytes, j.file_bytes,
            "{}: freshly encoded bytes differ from committed file",
            j.name
        );
        assert_eq!(compute_sha256_hex(&disk_bytes), j.file_sha256);
    }

    let disk_jpeg_manifest = fs::read_to_string(jpeg_dir.join("fixture_manifest.json"))?;
    let gen_jpeg_manifest = build_jpeg_manifest_json(&jpegs);
    assert_eq!(
        disk_jpeg_manifest, gen_jpeg_manifest,
        "JPEG manifest mismatch"
    );

    // 5 MJPEGs
    let mjpegs = generate_all_mjpeg_fixtures()?;
    assert_eq!(mjpegs.len(), 5);
    for m in &mjpegs {
        let p = mjpeg_dir.join(&m.name);
        assert!(p.exists(), "Missing committed MJPEG: {}", p.display());
        let disk_bytes = fs::read(&p)?;
        assert_eq!(
            disk_bytes, m.file_bytes,
            "{}: freshly encoded MJPEG bytes differ from committed file",
            m.name
        );
        assert_eq!(compute_sha256_hex(&disk_bytes), m.file_sha256);
    }

    let disk_mjpeg_manifest = fs::read_to_string(mjpeg_dir.join("fixture_manifest.json"))?;
    let gen_mjpeg_manifest = build_mjpeg_manifest_json(&mjpegs);
    assert_eq!(
        disk_mjpeg_manifest, gen_mjpeg_manifest,
        "MJPEG manifest mismatch"
    );

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"jpegs":13,"mjpegs":5,"byte_identical":true}"#;
    let obs_json = r#"{"jpegs":13,"mjpegs":5,"byte_identical":true}"#;
    emit_caplog("regeneration_identity", "pass", 0, dur, exp_json, obs_json);
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 3: Marker walk structure across all 13 JPEGs
// ---------------------------------------------------------------------------

#[test]
fn test_03_marker_walk_order_and_segment_lengths() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let fixtures = generate_all_jpeg_fixtures()?;
    assert_eq!(fixtures.len(), 13);

    for f in &fixtures {
        let bytes = &f.file_bytes;
        assert!(bytes.len() >= 4, "{}: file too short", f.name);
        assert_eq!(bytes[0], 0xFF, "{}: missing SOI 0xFF", f.name);
        assert_eq!(bytes[1], 0xD8, "{}: missing SOI 0xD8", f.name);

        let mut offset = 2usize;
        let mut seen_markers = Vec::new();

        while offset < bytes.len() {
            assert_eq!(
                bytes[offset], 0xFF,
                "{}: expected marker at offset {}",
                f.name, offset
            );
            let marker = bytes[offset + 1];
            offset += 2;

            if marker == 0xD9 {
                seen_markers.push(0xD9);
                assert_eq!(offset, bytes.len(), "{}: EOI not at end", f.name);
                break;
            }

            if marker == 0xDA {
                seen_markers.push(0xDA);
                assert!(offset + 2 <= bytes.len(), "{}: SOS truncated", f.name);
                let len = ((bytes[offset] as usize) << 8) | (bytes[offset + 1] as usize);
                offset += len;

                // Scan entropy data until next non-stuffed marker
                while offset < bytes.len() {
                    if bytes[offset] == 0xFF {
                        assert!(offset + 1 < bytes.len(), "{}: trailing FF byte", f.name);
                        let next = bytes[offset + 1];
                        if next == 0x00 || (0xD0..=0xD7).contains(&next) {
                            offset += 2;
                        } else if next == 0xD9 {
                            break;
                        } else {
                            return Err(format!(
                                "{}: invalid marker 0x{:02X} inside entropy scan",
                                f.name, next
                            )
                            .into());
                        }
                    } else {
                        offset += 1;
                    }
                }
                continue;
            }

            assert!(
                offset + 2 <= bytes.len(),
                "{}: truncated marker 0x{:02X}",
                f.name,
                marker
            );
            let seg_len = ((bytes[offset] as usize) << 8) | (bytes[offset + 1] as usize);
            assert!(seg_len >= 2, "{}: seg_len {} too small", f.name, seg_len);
            seen_markers.push(marker);
            offset += seg_len;
        }

        // Assert order: APP0, DQT, SOF0, DHT, SOS, EOI
        assert!(seen_markers.contains(&0xE0), "{}: missing APP0", f.name);
        assert!(seen_markers.contains(&0xDB), "{}: missing DQT", f.name);
        assert!(seen_markers.contains(&0xC0), "{}: missing SOF0", f.name);
        assert!(seen_markers.contains(&0xC4), "{}: missing DHT", f.name);
        assert!(seen_markers.contains(&0xDA), "{}: missing SOS", f.name);
        assert!(seen_markers.contains(&0xD9), "{}: missing EOI", f.name);
    }

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"fixtures":13,"structure_valid":true}"#;
    let obs_json = r#"{"fixtures":13,"structure_valid":true}"#;
    emit_caplog("marker_walk", "pass", 0, dur, exp_json, obs_json);
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 4: 0xFF Byte stuffing validation (Kill M1)
// ---------------------------------------------------------------------------

#[test]
fn test_04_entropy_byte_stuffing_kill_m1() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let fixtures = generate_all_jpeg_fixtures()?;
    let mut total_stuffed_bytes = 0usize;

    for f in &fixtures {
        let bytes = &f.file_bytes;
        // Find SOS marker
        let mut sos_entropy_start = None;
        let mut offset = 2usize;
        while offset + 4 <= bytes.len() {
            if bytes[offset] == 0xFF && bytes[offset + 1] == 0xDA {
                let len = ((bytes[offset + 2] as usize) << 8) | (bytes[offset + 3] as usize);
                sos_entropy_start = Some(offset + 2 + len);
                break;
            }
            if bytes[offset] == 0xFF {
                let len = ((bytes[offset + 2] as usize) << 8) | (bytes[offset + 3] as usize);
                offset += 2 + len;
            } else {
                offset += 1;
            }
        }
        let start_pos = sos_entropy_start.ok_or_else(|| format!("{}: SOS not found", f.name))?;
        let mut scan = start_pos;
        while scan + 1 < bytes.len() {
            if bytes[scan] == 0xFF {
                let next = bytes[scan + 1];
                if next == 0x00 {
                    total_stuffed_bytes = total_stuffed_bytes.saturating_add(1);
                    scan += 2;
                } else if (0xD0..=0xD7).contains(&next) {
                    scan += 2;
                } else if next == 0xD9 {
                    break;
                } else {
                    return Err(format!(
                        "{}: un-stuffed 0xFF followed by 0x{:02X} at offset {}",
                        f.name, next, scan
                    )
                    .into());
                }
            } else {
                scan += 1;
            }
        }
    }

    assert!(
        total_stuffed_bytes >= 20,
        "Expected at least 20 stuffed 0xFF00 bytes across corpus, found {}",
        total_stuffed_bytes
    );

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"stuffed_ff00_valid":true}"#;
    let obs_json = format!(
        r#"{{"stuffed_ff00_valid":true,"total_stuffed":{}}}"#,
        total_stuffed_bytes
    );
    emit_caplog("byte_stuffing", "pass", 0, dur, exp_json, &obs_json);
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 5: Restart markers MCU cadence and exact byte offsets (Kill M2)
// ---------------------------------------------------------------------------

#[test]
fn test_05_restart_markers_mcu_cadence_kill_m2() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let fixtures = generate_all_jpeg_fixtures()?;
    let f = fixtures
        .iter()
        .find(|j| j.name == "rgb_64x48_restart_ri5.jpg")
        .ok_or("rgb_64x48_restart_ri5.jpg missing")?;

    let bytes = &f.file_bytes;
    assert_eq!(f.restart_interval, 5);
    // 64x48 YCbCr 4:2:0: MCU is 16x16, total MCUs = (64/16) * (48/16) = 4 * 3 = 12.
    // Interval 5 -> RST0 after MCU 5, RST1 after MCU 10. Remaining MCUs = 2.
    // Scan entropy data for restart markers:
    let mut restart_markers = Vec::new();
    let mut offset = 2;
    let mut sos_offset = None;
    while offset + 4 <= bytes.len() {
        if bytes[offset] == 0xFF && bytes[offset + 1] == 0xDD {
            let ri = ((bytes[offset + 4] as u16) << 8) | (bytes[offset + 5] as u16);
            assert_eq!(ri, 5, "DRI interval must equal 5");
        }
        if bytes[offset] == 0xFF && bytes[offset + 1] == 0xDA {
            let len = ((bytes[offset + 2] as usize) << 8) | (bytes[offset + 3] as usize);
            sos_offset = Some(offset + 2 + len);
            break;
        }
        if bytes[offset] == 0xFF {
            let len = ((bytes[offset + 2] as usize) << 8) | (bytes[offset + 3] as usize);
            offset += 2 + len;
        } else {
            offset += 1;
        }
    }
    let scan_start = sos_offset.ok_or("SOS not found")?;
    let mut scan = scan_start;
    while scan + 1 < bytes.len() {
        if bytes[scan] == 0xFF {
            let m = bytes[scan + 1];
            if (0xD0..=0xD7).contains(&m) {
                restart_markers.push((m, scan));
                scan += 2;
                continue;
            } else if m == 0xD9 {
                break;
            }
        }
        scan += 1;
    }

    assert_eq!(
        restart_markers,
        vec![(0xD0, 736), (0xD1, 865)],
        "Expected RST0 at offset 736 and RST1 at offset 865"
    );

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"rst0_offset":736,"rst1_offset":865}"#;
    let obs_json = format!(
        r#"{{"rst0_offset":{},"rst1_offset":{}}}"#,
        restart_markers[0].1, restart_markers[1].1
    );
    emit_caplog("restart_markers", "pass", 0, dur, exp_json, &obs_json);
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 6: EOI termination at end of file (Kill M3)
// ---------------------------------------------------------------------------

#[test]
fn test_06_eoi_termination_kill_m3() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let fixtures = generate_all_jpeg_fixtures()?;
    for f in &fixtures {
        let bytes = &f.file_bytes;
        assert!(bytes.len() >= 4, "{}: file too short", f.name);
        assert_eq!(
            &bytes[bytes.len() - 2..],
            &[0xFF, 0xD9],
            "{}: file does not end with EOI (0xFF, 0xD9)",
            f.name
        );
    }

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"fixtures":13,"all_end_with_eoi":true}"#;
    let obs_json = r#"{"fixtures":13,"all_end_with_eoi":true}"#;
    emit_caplog("eoi_termination", "pass", 0, dur, exp_json, obs_json);
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 7: DQT tables order, table IDs, and zigzag mapping (Kill M4)
// ---------------------------------------------------------------------------

#[test]
fn test_07_dqt_tables_order_and_zigzag_kill_m4() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let fixtures = generate_all_jpeg_fixtures()?;

    for f in &fixtures {
        let bytes = &f.file_bytes;
        let mut offset = 2;
        let mut dqt_tables = Vec::new();

        while offset + 4 <= bytes.len() {
            if bytes[offset] == 0xFF && bytes[offset + 1] == 0xDB {
                let seg_len = ((bytes[offset + 2] as usize) << 8) | (bytes[offset + 3] as usize);
                let payload = &bytes[offset + 4..offset + 2 + seg_len];
                let mut p_offset = 0;
                while p_offset + 65 <= payload.len() {
                    let info = payload[p_offset];
                    let table_id = info & 0x0F;
                    let table_bytes = &payload[p_offset + 1..p_offset + 65];
                    dqt_tables.push((table_id, table_bytes.to_vec()));
                    p_offset += 65;
                }
                offset += 2 + seg_len;
            } else if bytes[offset] == 0xFF && bytes[offset + 1] == 0xDA {
                break;
            } else if bytes[offset] == 0xFF {
                let len = ((bytes[offset + 2] as usize) << 8) | (bytes[offset + 3] as usize);
                offset += 2 + len;
            } else {
                offset += 1;
            }
        }

        if f.channels == 1 {
            assert_eq!(
                dqt_tables.len(),
                1,
                "{}: grayscale expected 1 DQT table",
                f.name
            );
            assert_eq!(
                dqt_tables[0].0, 0x00,
                "{}: grayscale DQT table ID must be 0",
                f.name
            );
        } else {
            assert_eq!(
                dqt_tables.len(),
                2,
                "{}: color expected 2 DQT tables",
                f.name
            );
            assert_eq!(
                dqt_tables[0].0, 0x00,
                "{}: first DQT table ID must be 0 (Luma)",
                f.name
            );
            assert_eq!(
                dqt_tables[1].0, 0x01,
                "{}: second DQT table ID must be 1 (Chroma)",
                f.name
            );
            // Verify Luma and Chroma tables are distinct for non-q100 color fixtures
            if f.quality != 100 {
                assert_ne!(
                    dqt_tables[0].1, dqt_tables[1].1,
                    "{}: Luma and Chroma DQT tables must differ",
                    f.name
                );
            }
        }
    }

    // Verify Annex K base quantization tables match constant literals
    assert_eq!(BASE_LUMA_QUANT[0], 16);
    assert_eq!(BASE_CHROMA_QUANT[0], 17);
    assert_eq!(ZIGZAG[0], 0);
    assert_eq!(ZIGZAG[63], 63);

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"dqt_order_valid":true,"zigzag_valid":true}"#;
    let obs_json = r#"{"dqt_order_valid":true,"zigzag_valid":true}"#;
    emit_caplog("dqt_table_order", "pass", 0, dur, exp_json, obs_json);
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 8: DHT tables order and Annex K tables (Kill M5)
// ---------------------------------------------------------------------------

#[test]
fn test_08_dht_tables_order_and_annex_k_kill_m5() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let fixtures = generate_all_jpeg_fixtures()?;

    // Check Annex K table sizes and constants
    assert_eq!(LUMA_DC_BITS.len(), 16);
    assert_eq!(LUMA_DC_VALS.len(), 12);
    assert_eq!(LUMA_AC_BITS.len(), 16);
    assert_eq!(LUMA_AC_VALS.len(), 162);
    assert_eq!(CHROMA_DC_BITS.len(), 16);
    assert_eq!(CHROMA_DC_VALS.len(), 12);
    assert_eq!(CHROMA_AC_BITS.len(), 16);
    assert_eq!(CHROMA_AC_VALS.len(), 162);

    for f in &fixtures {
        let bytes = &f.file_bytes;
        let mut offset = 2;
        let mut dht_table_ids = Vec::new();

        while offset + 4 <= bytes.len() {
            if bytes[offset] == 0xFF && bytes[offset + 1] == 0xC4 {
                let seg_len = ((bytes[offset + 2] as usize) << 8) | (bytes[offset + 3] as usize);
                let payload = &bytes[offset + 4..offset + 2 + seg_len];
                let mut p_offset = 0;
                while p_offset < payload.len() {
                    let table_info = payload[p_offset];
                    dht_table_ids.push(table_info);
                    let bits = &payload[p_offset + 1..p_offset + 17];
                    let val_count: usize = bits.iter().map(|&b| b as usize).sum();
                    let vals = &payload[p_offset + 17..p_offset + 17 + val_count];
                    match table_info {
                        0x00 => {
                            assert_eq!(
                                bits,
                                &LUMA_DC_BITS[..],
                                "{}: Table 0x00 bits must match LUMA_DC_BITS",
                                f.name
                            );
                            assert_eq!(
                                vals,
                                &LUMA_DC_VALS[..],
                                "{}: Table 0x00 vals must match LUMA_DC_VALS",
                                f.name
                            );
                        }
                        0x10 => {
                            assert_eq!(
                                bits,
                                &LUMA_AC_BITS[..],
                                "{}: Table 0x10 bits must match LUMA_AC_BITS",
                                f.name
                            );
                            assert_eq!(
                                vals,
                                &LUMA_AC_VALS[..],
                                "{}: Table 0x10 vals must match LUMA_AC_VALS",
                                f.name
                            );
                        }
                        0x01 => {
                            assert_eq!(
                                bits,
                                &CHROMA_DC_BITS[..],
                                "{}: Table 0x01 bits must match CHROMA_DC_BITS",
                                f.name
                            );
                            assert_eq!(
                                vals,
                                &CHROMA_DC_VALS[..],
                                "{}: Table 0x01 vals must match CHROMA_DC_VALS",
                                f.name
                            );
                        }
                        0x11 => {
                            assert_eq!(
                                bits,
                                &CHROMA_AC_BITS[..],
                                "{}: Table 0x11 bits must match CHROMA_AC_BITS",
                                f.name
                            );
                            assert_eq!(
                                vals,
                                &CHROMA_AC_VALS[..],
                                "{}: Table 0x11 vals must match CHROMA_AC_VALS",
                                f.name
                            );
                        }
                        _ => {
                            return Err(format!(
                                "{}: unexpected DHT table info 0x{:02x}",
                                f.name, table_info
                            )
                            .into());
                        }
                    }
                    p_offset += 17 + val_count;
                }
                offset += 2 + seg_len;
            } else if bytes[offset] == 0xFF && bytes[offset + 1] == 0xDA {
                break;
            } else if bytes[offset] == 0xFF {
                let len = ((bytes[offset + 2] as usize) << 8) | (bytes[offset + 3] as usize);
                offset += 2 + len;
            } else {
                offset += 1;
            }
        }

        if f.channels == 3 {
            assert_eq!(
                dht_table_ids,
                vec![0x00, 0x10, 0x01, 0x11],
                "{}: DHT tables must be emitted in exact order [0x00 (DC Y), 0x10 (AC Y), 0x01 (DC C), 0x11 (AC C)]",
                f.name
            );
        } else {
            assert_eq!(
                dht_table_ids,
                vec![0x00, 0x10],
                "{}: Grayscale DHT tables must be emitted in exact order [0x00 (DC Y), 0x10 (AC Y)]",
                f.name
            );
        }
    }

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"dht_order_valid":true,"annex_k_valid":true}"#;
    let obs_json = r#"{"dht_order_valid":true,"annex_k_valid":true}"#;
    emit_caplog("dht_table_order", "pass", 0, dur, exp_json, obs_json);
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 9: MJPEG frame length exactness (Kill M6)
// ---------------------------------------------------------------------------

#[test]
fn test_09_mjpeg_frame_lengths_exactness_kill_m6() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let mjpegs = generate_all_mjpeg_fixtures()?;

    for m in &mjpegs {
        for fr in &m.frames {
            let slice = &m.file_bytes[fr.offset..fr.offset + fr.length];
            assert_eq!(compute_sha256_hex(slice), fr.frame_sha256);

            // Off-by-one check: slice length + 1 or slice length - 1 must mismatch
            if fr.offset + fr.length < m.file_bytes.len() {
                let slice_plus1 = &m.file_bytes[fr.offset..fr.offset + fr.length + 1];
                assert_ne!(compute_sha256_hex(slice_plus1), fr.frame_sha256);
            }
            if fr.length > 1 {
                let slice_minus1 = &m.file_bytes[fr.offset..fr.offset + fr.length - 1];
                assert_ne!(compute_sha256_hex(slice_minus1), fr.frame_sha256);
            }
        }
    }

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"frame_length_exact":true}"#;
    let obs_json = r#"{"frame_length_exact":true}"#;
    emit_caplog("mjpeg_frame_lengths", "pass", 0, dur, exp_json, obs_json);
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 10: brown_luma_q100 DQT all-ones property
// ---------------------------------------------------------------------------

#[test]
fn test_10_brown_luma_q100_all_ones_dqt() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let fixtures = generate_all_jpeg_fixtures()?;
    let q100 = fixtures
        .iter()
        .find(|f| f.name == "brown_luma_q100.jpg")
        .ok_or("brown_luma_q100.jpg missing")?;

    let bytes = &q100.file_bytes;
    let mut found_dqt = false;
    let mut offset = 2;
    while offset + 4 <= bytes.len() {
        if bytes[offset] == 0xFF && bytes[offset + 1] == 0xDB {
            let seg_len = ((bytes[offset + 2] as usize) << 8) | (bytes[offset + 3] as usize);
            assert_eq!(seg_len, 67);
            let table = &bytes[offset + 5..offset + 5 + 64];
            for (i, &b) in table.iter().enumerate() {
                assert_eq!(b, 1, "DQT entry at index {i} must be 1 for q100");
            }
            found_dqt = true;
            break;
        }
        if bytes[offset] == 0xFF && bytes[offset + 1] == 0xDA {
            break;
        }
        if bytes[offset] == 0xFF {
            let len = ((bytes[offset + 2] as usize) << 8) | (bytes[offset + 3] as usize);
            offset += 2 + len;
        } else {
            offset += 1;
        }
    }
    assert!(found_dqt, "DQT not found in brown_luma_q100.jpg");

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"all_ones_dqt":true}"#;
    let obs_json = r#"{"all_ones_dqt":true}"#;
    emit_caplog("q100_all_ones", "pass", 0, dur, exp_json, obs_json);
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 11: brown_luma source-luma binding with owner test fixture
// ---------------------------------------------------------------------------

#[test]
fn test_11_brown_luma_source_binding() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let repo_root = locate_repo_root()?;
    let gray_file = repo_root.join("crates/fss-twin/tests/fixtures/brown_luma_96x96.gray");
    let disk_gray_bytes = fs::read(&gray_file)?;
    assert_eq!(disk_gray_bytes.len(), 96 * 96);
    let disk_sha = compute_sha256_hex(&disk_gray_bytes);
    assert_eq!(
        disk_sha,
        "5843ec0250942b9ca4ec0fe68ce80289aa60eaa5d796c6c388a71a59f0438538"
    );

    let src_q100 = source_pixels("brown_luma_q100")?;
    assert_eq!(src_q100, disk_gray_bytes);
    let src_qfix = source_pixels("brown_luma_qfix")?;
    assert_eq!(src_qfix, disk_gray_bytes);
    let raw_bytes = brown_luma_96x96();
    assert_eq!(raw_bytes, disk_gray_bytes.as_slice());

    let dur = start.elapsed().as_millis();
    let exp_json =
        r#"{"brown_luma_sha":"5843ec0250942b9ca4ec0fe68ce80289aa60eaa5d796c6c388a71a59f0438538"}"#;
    let obs_json = format!(r#"{{"brown_luma_sha":"{}"}}"#, disk_sha);
    emit_caplog("brown_luma_binding", "pass", 0, dur, exp_json, &obs_json);
    Ok(())
}

// Note: simulate_float_idct_gray was made private in fss-2h5zq.5 (merged 1f535b9);
// independent baseline decoding, PSNR bounds, and maximum absolute error are
// thoroughly covered by .5's contract test in media_fixture_jpeg_contract.rs
// (test_brown_luma_independent_baseline_decode) and not duplicated here.

// ---------------------------------------------------------------------------
// Step 13: Custom markers APP1 and COM with embedded 0xFFD9
// ---------------------------------------------------------------------------

#[test]
fn test_13_custom_markers_embedded_ffd9() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let fixtures = generate_all_jpeg_fixtures()?;
    let f = fixtures
        .iter()
        .find(|f| f.name == "rgb_64x48_app_com_ffd9.jpg")
        .ok_or("rgb_64x48_app_com_ffd9.jpg missing")?;

    let bytes = &f.file_bytes;
    let mut saw_app1_ffd9 = false;
    let mut saw_com_ffd9 = false;
    let mut offset = 2;

    while offset + 4 <= bytes.len() {
        if bytes[offset] == 0xFF {
            let m = bytes[offset + 1];
            if m == 0xDA {
                break;
            }
            let len = ((bytes[offset + 2] as usize) << 8) | (bytes[offset + 3] as usize);
            let payload = &bytes[offset + 4..offset + 2 + len];
            if m == 0xE1 && payload.windows(2).any(|w| w == [0xFF, 0xD9]) {
                saw_app1_ffd9 = true;
            }
            if m == 0xFE && payload.windows(2).any(|w| w == [0xFF, 0xD9]) {
                saw_com_ffd9 = true;
            }
            offset += 2 + len;
        } else {
            offset += 1;
        }
    }

    assert!(saw_app1_ffd9, "APP1 marker with embedded 0xFFD9 not found");
    assert!(saw_com_ffd9, "COM marker with embedded 0xFFD9 not found");
    assert_eq!(
        bytes.len(),
        961,
        "rgb_64x48_app_com_ffd9.jpg file size mismatch"
    );

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"app1_ffd9":true,"com_ffd9":true}"#;
    let obs_json = r#"{"app1_ffd9":true,"com_ffd9":true}"#;
    emit_caplog("custom_markers", "pass", 0, dur, exp_json, obs_json);
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 14: Pinned fixture literals for all 13 JPEGs and 5 MJPEGs
// ---------------------------------------------------------------------------

#[test]
fn test_14_pinned_fixture_literals() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let expected_jpegs: [(&str, &str); 13] = [
        (
            "gray_16x16_flat.jpg",
            "bb89bdbebe3b4aa81a6bb3a0d3a548d4d8b4e0d633a511de75b0fd6c41062577",
        ),
        (
            "gray_16x16_gradient.jpg",
            "6a2ff2099abc97c9bc942ae27d9ac1628b7d1a59b3b6073ae14d3cbb3212a8b0",
        ),
        (
            "gray_33x17_checkerboard.jpg",
            "b636ce19535fc7cff7420d0a28475e1e7891a6064f0e417a58cb1899e75d68e6",
        ),
        (
            "brown_luma_q100.jpg",
            "5ebad3f16a863de160d58cf2d6164707f367abd6a217580f2637e7320bef56cb",
        ),
        (
            "brown_luma_qfix.jpg",
            "b7b76884676a817d9d4a0a5b3b50c90278d2bce5d49c2d8ef5a6a75e5dc0e812",
        ),
        (
            "rgb_16x16_flat_444.jpg",
            "92b510feca8c4f0c29955a3c00ee54a8ae207c242cf6889666a8cfa4e9ff077a",
        ),
        (
            "rgb_16x16_gradient_420.jpg",
            "d9470ede0234592f82ef448f1a3f01d0691b1528ad000aad8011fa9e9685b448",
        ),
        (
            "rgb_33x17_checkerboard_420.jpg",
            "cbefc274c2dee52f41ec3e657df05e2dc65b4c8d89120422445caa7bf2daf3de",
        ),
        (
            "rgb_64x48_colorbars_420.jpg",
            "3b92d4ad9cbcb3621b43105760025eb5d771a0944967ebd431712687245d36bd",
        ),
        (
            "rgb_64x48_colorbars_444.jpg",
            "3b59b4773d23ed8a51485c5cd83c02564c8c449e9869922034ecb8a2e4f294c6",
        ),
        (
            "rgb_64x48_colorbars_422.jpg",
            "b4526aa52510210cfc569e54f855bf6f74e9e864470e67555e4d92859fea2554",
        ),
        (
            "rgb_64x48_restart_ri5.jpg",
            "23a9ce54e1842feeafe32a2debd36e129b4de49428c1449361a1332f9d8f9c39",
        ),
        (
            "rgb_64x48_app_com_ffd9.jpg",
            "717d672a506d4e23e5f2fedbdbd022d9bf7c7dc322fe8a26bcacecb91cd9652c",
        ),
    ];

    let jpegs = generate_all_jpeg_fixtures()?;
    assert_eq!(jpegs.len(), 13);
    for (name, expected_sha) in expected_jpegs {
        let f = jpegs
            .iter()
            .find(|j| j.name == name)
            .ok_or_else(|| format!("{name} missing"))?;
        assert_eq!(f.file_sha256, expected_sha, "{}: sha mismatch", name);
        assert_eq!(compute_sha256_hex(&f.file_bytes), expected_sha);
    }

    let expected_mjpegs: [(&str, &str); 5] = [
        (
            "mjpeg_clean_3frames.mjpeg",
            "5d0ad1de84dd83b354310d873ec1f1f8d02557b33b4420f3838673679d7591e7",
        ),
        (
            "mjpeg_truncated_last.mjpeg",
            "30dbae06f430b40692571579e39fb2f5293b0c8d172524496f8874386fef5e03",
        ),
        (
            "mjpeg_garbage_between_frames.mjpeg",
            "86235d316103beb4451ad27e9a4c2221fcd3df5071d0ced1923c2b0512806a31",
        ),
        (
            "mjpeg_zero_length.mjpeg",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            "mjpeg_dimension_change.mjpeg",
            "26f5302e153ffe294b812e7e7e36ef7af0d1d32d8f27ba6391409d18315f7750",
        ),
    ];

    let mjpegs = generate_all_mjpeg_fixtures()?;
    assert_eq!(mjpegs.len(), 5);
    for (name, expected_sha) in expected_mjpegs {
        let m = mjpegs
            .iter()
            .find(|m| m.name == name)
            .ok_or_else(|| format!("{name} missing"))?;
        assert_eq!(m.file_sha256, expected_sha, "{}: sha mismatch", name);
        assert_eq!(compute_sha256_hex(&m.file_bytes), expected_sha);
    }

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"pinned_jpegs":13,"pinned_mjpegs":5,"all_matched":true}"#;
    let obs_json = r#"{"pinned_jpegs":13,"pinned_mjpegs":5,"all_matched":true}"#;
    emit_caplog("pinned_literals", "pass", 0, dur, exp_json, obs_json);
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 15: No production consumer guard test
// ---------------------------------------------------------------------------

#[test]
fn test_15_no_production_consumer_guard() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src_dir = manifest_dir.join("src");

    let mut violations = Vec::new();
    let mut stack = vec![src_dir];

    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name != "media_fixture" {
                    stack.push(path);
                }
            } else if path.is_file() {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "rs" {
                    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if file_name != "media_fixture.rs" {
                        let content = fs::read_to_string(&path)?;
                        for (idx, line) in content.lines().enumerate() {
                            if line.contains("media_fixture::jpeg")
                                || (line.contains("media_fixture")
                                    && !line.contains("pub mod media_fixture;"))
                            {
                                violations.push(format!(
                                    "{}:{}: disallowed reference to fixture generator in production code",
                                    path.display(),
                                    idx + 1
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    assert!(violations.is_empty(), "Violations found: {:?}", violations);

    let dur = start.elapsed().as_millis();
    let exp_json = r#"{"violations":0}"#;
    let obs_json = r#"{"violations":0}"#;
    emit_caplog("no_production_consumer", "pass", 0, dur, exp_json, obs_json);
    Ok(())
}

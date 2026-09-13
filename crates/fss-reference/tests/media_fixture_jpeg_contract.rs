#![forbid(unsafe_code)]
//! Contract tests for baseline JPEG and MJPEG media fixture generators.
//!
//! Verifies:
//! - Deterministic, bit-identical fixture generation for baseline JPEGs and MJPEGs.
//! - Marker walk correctness (SOI, APP0, DQT, SOF0, DHT, SOS, EOI, RSTn).
//! - Byte-stuffing in entropy-coded scan data (0xFF followed by 0x00 or RSTn).
//! - Quality 100 all-ones DQT matrix verification.
//! - Brown-Conrady distorted luma source byte-parity with owner test fixture.
//! - Float IDCT simulation, PSNR bounds, and maximum absolute error checks.
//! - Embedded marker edge cases (APPn/COM containing 0xFFD9 payload bytes).
//! - Restart marker cadence and interval verification.
//! - 5 MJPEG variant streams (clean, truncated_last, garbage_between_frames, zero_length, dimension_change).
//! - Manifest integrity and source pixel regeneration match.
//! - Guard test ensuring no production consumer calls fixture generation.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_reference::media_fixture::jpeg::{
    brown_luma_96x96, build_jpeg_manifest_json, build_mjpeg_manifest_json, compute_sha256_hex,
    generate_all_jpeg_fixtures, generate_all_mjpeg_fixtures, simulate_float_idct_gray,
    source_pixels,
};

#[test]
fn test_no_production_consumer_guard() -> Result<(), Box<dyn Error>> {
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

    assert!(
        violations.is_empty(),
        "Production code must not depend on media_fixture generator: {:?}",
        violations
    );
    Ok(())
}

#[test]
fn test_jpeg_marker_walk_and_structure() -> Result<(), Box<dyn Error>> {
    let fixtures = generate_all_jpeg_fixtures()?;
    assert_eq!(fixtures.len(), 13, "Expected 13 normative JPEG fixtures");

    for fixture in &fixtures {
        let bytes = &fixture.file_bytes;
        assert!(bytes.len() >= 4, "{}: file too short", fixture.name);

        // SOI check
        assert_eq!(bytes[0], 0xFF, "{}: missing SOI 0xFF", fixture.name);
        assert_eq!(bytes[1], 0xD8, "{}: missing SOI 0xD8", fixture.name);

        let mut offset = 2usize;
        let mut saw_app0 = false;
        let mut saw_dqt = false;
        let mut saw_sof0 = false;
        let mut saw_dht = false;
        let mut saw_sos = false;

        while offset < bytes.len() {
            assert_eq!(
                bytes[offset], 0xFF,
                "{}: expected marker at offset {}",
                fixture.name, offset
            );
            let marker = bytes[offset + 1];
            offset += 2;

            if marker == 0xD9 {
                // EOI
                assert_eq!(
                    offset,
                    bytes.len(),
                    "{}: EOI not at end of file",
                    fixture.name
                );
                break;
            }

            if marker == 0xDA {
                // SOS - start of scan
                saw_sos = true;
                assert!(offset + 2 <= bytes.len(), "{}: SOS truncated", fixture.name);
                let len = ((bytes[offset] as usize) << 8) | (bytes[offset + 1] as usize);
                offset += len;

                // Scan entropy-coded data until EOI
                while offset < bytes.len() {
                    if bytes[offset] == 0xFF {
                        assert!(
                            offset + 1 < bytes.len(),
                            "{}: trailing FF byte",
                            fixture.name
                        );
                        let next = bytes[offset + 1];
                        if next == 0x00 {
                            // Byte-stuffed 0xFF
                            offset += 2;
                        } else if (0xD0..=0xD7).contains(&next) {
                            // Restart marker
                            offset += 2;
                        } else if next == 0xD9 {
                            // Real EOI
                            break;
                        } else {
                            return Err(format!(
                                "{}: invalid byte after 0xFF in entropy scan: 0x{:02X} at offset {}",
                                fixture.name, next, offset
                            )
                            .into());
                        }
                    } else {
                        offset += 1;
                    }
                }
                continue;
            }

            // Variable-length marker segment
            assert!(
                offset + 2 <= bytes.len(),
                "{}: marker 0x{:02X} truncated length",
                fixture.name,
                marker
            );
            let seg_len = ((bytes[offset] as usize) << 8) | (bytes[offset + 1] as usize);
            assert!(
                seg_len >= 2,
                "{}: marker segment length too small: {}",
                fixture.name,
                seg_len
            );
            let seg_payload = &bytes[offset + 2..offset + seg_len];

            match marker {
                0xE0 => {
                    // APP0
                    saw_app0 = true;
                    assert!(seg_payload.len() >= 5, "{}: APP0 too short", fixture.name);
                    assert_eq!(
                        &seg_payload[0..5],
                        b"JFIF\0",
                        "{}: APP0 missing JFIF tag",
                        fixture.name
                    );
                }
                0xDB => {
                    // DQT
                    saw_dqt = true;
                }
                0xC0 => {
                    // SOF0 (Baseline DCT)
                    saw_sof0 = true;
                    assert!(
                        seg_payload.len() >= 6,
                        "{}: SOF0 payload too short",
                        fixture.name
                    );
                    let precision = seg_payload[0];
                    assert_eq!(precision, 8, "{}: sample precision must be 8", fixture.name);
                    let height = ((seg_payload[1] as u32) << 8) | (seg_payload[2] as u32);
                    let width = ((seg_payload[3] as u32) << 8) | (seg_payload[4] as u32);
                    assert_eq!(
                        width, fixture.width,
                        "{}: width mismatch in SOF0",
                        fixture.name
                    );
                    assert_eq!(
                        height, fixture.height,
                        "{}: height mismatch in SOF0",
                        fixture.name
                    );
                    let num_components = seg_payload[5];
                    assert_eq!(
                        num_components, fixture.channels,
                        "{}: channel count mismatch in SOF0",
                        fixture.name
                    );
                }
                0xC4 => {
                    // DHT
                    saw_dht = true;
                }
                0xDD => {
                    // DRI
                    assert_eq!(
                        seg_payload.len(),
                        2,
                        "{}: DRI payload length != 2",
                        fixture.name
                    );
                    let ri = ((seg_payload[0] as u16) << 8) | (seg_payload[1] as u16);
                    assert_eq!(
                        ri, fixture.restart_interval,
                        "{}: DRI interval mismatch",
                        fixture.name
                    );
                }
                _ => {
                    // Other markers like APP1, COM
                }
            }

            offset += seg_len;
        }

        assert!(saw_app0, "{}: missing APP0 marker", fixture.name);
        assert!(saw_dqt, "{}: missing DQT marker", fixture.name);
        assert!(saw_sof0, "{}: missing SOF0 marker", fixture.name);
        assert!(saw_dht, "{}: missing DHT marker", fixture.name);
        assert!(saw_sos, "{}: missing SOS marker", fixture.name);
    }

    Ok(())
}

#[test]
fn test_brown_luma_q100_all_ones_dqt() -> Result<(), Box<dyn Error>> {
    let fixtures = generate_all_jpeg_fixtures()?;
    let q100 = fixtures
        .iter()
        .find(|f| f.name == "brown_luma_q100.jpg")
        .ok_or("brown_luma_q100.jpg fixture missing")?;

    let bytes = &q100.file_bytes;
    let mut found_dqt = false;
    let mut offset = 2;
    while offset + 4 <= bytes.len() {
        if bytes[offset] == 0xFF && bytes[offset + 1] == 0xDB {
            let seg_len = ((bytes[offset + 2] as usize) << 8) | (bytes[offset + 3] as usize);
            assert_eq!(seg_len, 67, "DQT length should be 67 for 8-bit table");
            let table_info = bytes[offset + 4];
            assert_eq!(table_info, 0x00, "Table info should be 0 (luma, 8-bit)");
            let table = &bytes[offset + 5..offset + 5 + 64];
            for (idx, &entry) in table.iter().enumerate() {
                assert_eq!(entry, 1, "DQT entry at {} must be 1 for q100", idx);
            }
            found_dqt = true;
            break;
        }
        if bytes[offset] == 0xFF && bytes[offset + 1] == 0xDA {
            break;
        }
        if bytes[offset] == 0xFF && bytes[offset + 1] != 0x00 {
            let len = ((bytes[offset + 2] as usize) << 8) | (bytes[offset + 3] as usize);
            offset += 2 + len;
        } else {
            offset += 1;
        }
    }
    assert!(found_dqt, "DQT marker not found in brown_luma_q100.jpg");
    Ok(())
}

#[test]
fn test_brown_luma_source_parity() -> Result<(), Box<dyn Error>> {
    let ref_bytes = brown_luma_96x96();
    assert_eq!(ref_bytes.len(), 96 * 96);
    let ref_sha = compute_sha256_hex(ref_bytes);

    let src_q100 = source_pixels("brown_luma_q100")?;
    assert_eq!(src_q100.len(), 96 * 96);
    assert_eq!(src_q100, ref_bytes);
    assert_eq!(compute_sha256_hex(&src_q100), ref_sha);

    let src_qfix = source_pixels("brown_luma_qfix")?;
    assert_eq!(src_qfix.len(), 96 * 96);
    assert_eq!(src_qfix, ref_bytes);
    assert_eq!(compute_sha256_hex(&src_qfix), ref_sha);

    Ok(())
}

#[test]
fn test_brown_luma_float_idct_simulation() -> Result<(), Box<dyn Error>> {
    let ref_bytes = brown_luma_96x96();

    // q100 simulation
    let (_, psnr_q100, max_err_q100) = simulate_float_idct_gray(96, 96, ref_bytes, 100)?;
    assert!(
        psnr_q100 >= 58.0,
        "q100 PSNR must be >= 58 dB, got {psnr_q100:.2}"
    );
    assert!(
        max_err_q100 <= 1,
        "q100 max error must be <= 1, got {max_err_q100}"
    );

    // qfix (quality 90) simulation
    let (_, psnr_qfix, max_err_qfix) = simulate_float_idct_gray(96, 96, ref_bytes, 90)?;
    assert!(
        psnr_qfix >= 30.0,
        "qfix PSNR must be >= 30 dB, got {psnr_qfix:.2}"
    );
    assert!(
        max_err_qfix <= 20,
        "qfix max error must be <= 20, got {max_err_qfix}"
    );

    // Verify fixtures have recorded these values
    let fixtures = generate_all_jpeg_fixtures()?;
    for f in &fixtures {
        if f.channels == 1 {
            assert!(f.encoder_psnr.is_some(), "{}: missing encoder_psnr", f.name);
            assert!(
                f.encoder_max_error.is_some(),
                "{}: missing encoder_max_error",
                f.name
            );
            let psnr = f.encoder_psnr.ok_or("psnr missing")?;
            assert!(
                psnr >= 30.0,
                "{}: PSNR {psnr:.2} < 30.0 dB threshold",
                f.name
            );
        }
    }

    Ok(())
}

#[test]
fn test_custom_markers_app1_com_ffd9() -> Result<(), Box<dyn Error>> {
    let fixtures = generate_all_jpeg_fixtures()?;
    let f = fixtures
        .iter()
        .find(|f| f.name == "rgb_64x48_app_com_ffd9.jpg")
        .ok_or("rgb_64x48_app_com_ffd9.jpg fixture missing")?;

    let bytes = &f.file_bytes;
    let mut found_app1 = false;
    let mut found_com = false;
    let mut offset = 2;

    while offset + 4 <= bytes.len() {
        if bytes[offset] == 0xFF {
            let m = bytes[offset + 1];
            if m == 0xDA {
                break;
            }
            let len = ((bytes[offset + 2] as usize) << 8) | (bytes[offset + 3] as usize);
            let payload = &bytes[offset + 4..offset + 2 + len];
            if m == 0xE1 {
                found_app1 = true;
                assert!(
                    payload.windows(2).any(|w| w == [0xFF, 0xD9]),
                    "APP1 must contain 0xFF 0xD9 sequence"
                );
            } else if m == 0xFE {
                found_com = true;
                assert!(
                    payload.windows(2).any(|w| w == [0xFF, 0xD9]),
                    "COM must contain 0xFF 0xD9 sequence"
                );
            }
            offset += 2 + len;
        } else {
            offset += 1;
        }
    }

    assert!(
        found_app1,
        "APP1 marker not found in rgb_64x48_app_com_ffd9.jpg"
    );
    assert!(
        found_com,
        "COM marker not found in rgb_64x48_app_com_ffd9.jpg"
    );
    Ok(())
}

#[test]
fn test_restart_markers() -> Result<(), Box<dyn Error>> {
    let fixtures = generate_all_jpeg_fixtures()?;
    let f = fixtures
        .iter()
        .find(|f| f.name == "rgb_64x48_restart_ri3.jpg")
        .ok_or("rgb_64x48_restart_ri3.jpg fixture missing")?;

    let bytes = &f.file_bytes;
    // Check DRI
    let mut dri_found = false;
    let mut sos_offset = 0;
    let mut offset = 2;
    while offset + 4 <= bytes.len() {
        if bytes[offset] == 0xFF && bytes[offset + 1] == 0xDD {
            let ri = ((bytes[offset + 4] as u16) << 8) | (bytes[offset + 5] as u16);
            assert_eq!(ri, 3, "DRI interval must be 3");
            dri_found = true;
        }
        if bytes[offset] == 0xFF && bytes[offset + 1] == 0xDA {
            let len = ((bytes[offset + 2] as usize) << 8) | (bytes[offset + 3] as usize);
            sos_offset = offset + 2 + len;
            break;
        }
        if bytes[offset] == 0xFF {
            let len = ((bytes[offset + 2] as usize) << 8) | (bytes[offset + 3] as usize);
            offset += 2 + len;
        } else {
            offset += 1;
        }
    }
    assert!(dri_found, "DRI marker not found in restart fixture");
    assert!(sos_offset > 0, "SOS marker not found");

    // Scan for restart markers RST0, RST1, RST2 in entropy data
    let mut restart_markers = Vec::new();
    let mut scan = sos_offset;
    while scan + 1 < bytes.len() {
        if bytes[scan] == 0xFF {
            let m = bytes[scan + 1];
            if (0xD0..=0xD7).contains(&m) {
                restart_markers.push(m);
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
        vec![0xD0, 0xD1, 0xD2],
        "Expected restart markers RST0, RST1, RST2 in sequence"
    );
    Ok(())
}

#[test]
fn test_mjpeg_variants_structure() -> Result<(), Box<dyn Error>> {
    let mjpegs = generate_all_mjpeg_fixtures()?;
    assert_eq!(mjpegs.len(), 5, "Expected 5 MJPEG fixtures");

    for m in &mjpegs {
        match m.variant.as_str() {
            "clean" => {
                assert_eq!(m.frame_count, 3);
                assert_eq!(m.frames.len(), 3);
                let soi_count = count_subsequences(&m.file_bytes, &[0xFF, 0xD8]);
                let eoi_count = count_subsequences(&m.file_bytes, &[0xFF, 0xD9]);
                assert_eq!(soi_count, 3);
                assert_eq!(eoi_count, 3);
            }
            "truncated_last" => {
                assert_eq!(m.frame_count, 3);
                assert_eq!(m.frames.len(), 3);
                let soi_count = count_subsequences(&m.file_bytes, &[0xFF, 0xD8]);
                let eoi_count = count_subsequences(&m.file_bytes, &[0xFF, 0xD9]);
                assert_eq!(soi_count, 3);
                assert_eq!(eoi_count, 2, "Truncated last stream should have 2 EOIs");
            }
            "garbage_between_frames" => {
                assert_eq!(m.frame_count, 3);
                let soi_count = count_subsequences(&m.file_bytes, &[0xFF, 0xD8]);
                let eoi_count = count_subsequences(&m.file_bytes, &[0xFF, 0xD9]);
                assert_eq!(soi_count, 3);
                assert_eq!(eoi_count, 3);
                assert!(
                    m.file_bytes
                        .windows(b"GARBAGE".len())
                        .any(|w| w == b"GARBAGE")
                );
            }
            "zero_length" => {
                assert_eq!(m.frame_count, 0);
                assert_eq!(m.file_bytes.len(), 0);
            }
            "dimension_change" => {
                assert_eq!(m.frame_count, 2);
                assert_eq!(m.frames.len(), 2);
                assert_eq!(m.frames[0].width, 16);
                assert_eq!(m.frames[0].height, 16);
                assert_eq!(m.frames[1].width, 64);
                assert_eq!(m.frames[1].height, 48);
            }
            _ => return Err(format!("Unknown variant: {}", m.variant).into()),
        }
    }
    Ok(())
}

fn count_subsequences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|&w| w == needle)
        .count()
}

#[test]
fn test_source_pixels_regeneration_manifest_match() -> Result<(), Box<dyn Error>> {
    let jpegs = generate_all_jpeg_fixtures()?;
    for j in &jpegs {
        let src = source_pixels(&j.name)?;
        assert_eq!(src, j.source_bytes, "{}: source_pixels mismatch", j.name);
        assert_eq!(
            compute_sha256_hex(&src),
            j.source_pixel_sha256,
            "{}: source sha mismatch",
            j.name
        );
    }

    let mjpegs = generate_all_mjpeg_fixtures()?;
    for m in &mjpegs {
        let src = source_pixels(&m.name)?;
        assert_eq!(
            compute_sha256_hex(&src),
            m.source_pixel_sha256,
            "{}: mjpeg source sha mismatch",
            m.name
        );
    }
    Ok(())
}

#[test]
fn test_manifest_schemas() -> Result<(), Box<dyn Error>> {
    let jpegs = generate_all_jpeg_fixtures()?;
    let manifest_jpeg = build_jpeg_manifest_json(&jpegs);
    assert!(manifest_jpeg.contains(r#""schema": "fss.jpeg_fixture_manifest.v1""#));
    assert!(manifest_jpeg.contains(r#""brown_luma_q100.jpg""#));
    assert!(manifest_jpeg.contains(r#""brown_luma_qfix.jpg""#));

    let mjpegs = generate_all_mjpeg_fixtures()?;
    let manifest_mjpeg = build_mjpeg_manifest_json(&mjpegs);
    assert!(manifest_mjpeg.contains(r#""schema": "fss.mjpeg_fixture_manifest.v1""#));
    assert!(manifest_mjpeg.contains(r#""mjpeg_clean_3frames.mjpeg""#));
    assert!(manifest_mjpeg.contains(r#""mjpeg_truncated_last.mjpeg""#));

    Ok(())
}

#[test]
fn test_on_disk_fixtures_match_regeneration() -> Result<(), Box<dyn Error>> {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .ok_or("Failed to locate repo root")?;

    let jpeg_dir = repo_root.join("tests/fixtures/media/jpeg");
    let mjpeg_dir = repo_root.join("tests/fixtures/media/mjpeg");

    if jpeg_dir.join("fixture_manifest.json").exists() {
        let jpegs = generate_all_jpeg_fixtures()?;
        for j in &jpegs {
            let p = jpeg_dir.join(&j.name);
            assert!(p.exists(), "Committed fixture missing: {}", p.display());
            let disk_bytes = fs::read(&p)?;
            assert_eq!(
                disk_bytes, j.file_bytes,
                "Committed fixture bytes differ from generator: {}",
                j.name
            );
            assert_eq!(compute_sha256_hex(&disk_bytes), j.file_sha256);
        }
        let manifest_disk = fs::read_to_string(jpeg_dir.join("fixture_manifest.json"))?;
        let manifest_gen = build_jpeg_manifest_json(&jpegs);
        assert_eq!(
            manifest_disk, manifest_gen,
            "JPEG manifest differs from generator"
        );
    }

    if mjpeg_dir.join("fixture_manifest.json").exists() {
        let mjpegs = generate_all_mjpeg_fixtures()?;
        for m in &mjpegs {
            let p = mjpeg_dir.join(&m.name);
            assert!(
                p.exists(),
                "Committed MJPEG fixture missing: {}",
                p.display()
            );
            let disk_bytes = fs::read(&p)?;
            assert_eq!(
                disk_bytes, m.file_bytes,
                "Committed MJPEG bytes differ from generator: {}",
                m.name
            );
            assert_eq!(compute_sha256_hex(&disk_bytes), m.file_sha256);
        }
        let manifest_disk = fs::read_to_string(mjpeg_dir.join("fixture_manifest.json"))?;
        let manifest_gen = build_mjpeg_manifest_json(&mjpegs);
        assert_eq!(
            manifest_disk, manifest_gen,
            "MJPEG manifest differs from generator"
        );
    }

    Ok(())
}

#[test]
fn test_dump_fixtures_for_export() -> Result<(), Box<dyn Error>> {
    if std::env::var("EXPORT_MEDIA_FIXTURES").as_deref() == Ok("1") {
        let jpegs = generate_all_jpeg_fixtures()?;
        for j in &jpegs {
            println!("EXPORT_FILE_BEGIN:tests/fixtures/media/jpeg/{}", j.name);
            println!("{}", hex_encode(&j.file_bytes));
            println!("EXPORT_FILE_END");
        }
        println!("EXPORT_FILE_BEGIN:tests/fixtures/media/jpeg/fixture_manifest.json");
        let manifest_jpeg = build_jpeg_manifest_json(&jpegs);
        println!("{}", hex_encode(manifest_jpeg.as_bytes()));
        println!("EXPORT_FILE_END");

        let mjpegs = generate_all_mjpeg_fixtures()?;
        for m in &mjpegs {
            println!("EXPORT_FILE_BEGIN:tests/fixtures/media/mjpeg/{}", m.name);
            println!("{}", hex_encode(&m.file_bytes));
            println!("EXPORT_FILE_END");
        }
        println!("EXPORT_FILE_BEGIN:tests/fixtures/media/mjpeg/fixture_manifest.json");
        let manifest_mjpeg = build_mjpeg_manifest_json(&mjpegs);
        println!("{}", hex_encode(manifest_mjpeg.as_bytes()));
        println!("EXPORT_FILE_END");
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

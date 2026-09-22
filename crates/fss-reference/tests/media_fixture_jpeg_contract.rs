#![forbid(unsafe_code)]
//! Contract tests for baseline JPEG and MJPEG media fixture generators.
//!
//! Verifies:
//! - Deterministic, bit-identical fixture generation for baseline JPEGs and MJPEGs.
//! - Marker walk correctness (SOI, APP0, DQT, SOF0, DHT, SOS, EOI, RSTn).
//! - Byte-stuffing in entropy-coded scan data (0xFF followed by 0x00 or RSTn).
//! - Quality 100 all-ones DQT matrix verification.
//! - Brown-Conrady distorted luma source byte-parity with owner test fixture.
//! - Independent test-side baseline decode of the emitted bytes (DQT/DHT parsed from the
//!   file, Huffman decode, dequantize, float IDCT): PSNR bounds, maximum absolute error,
//!   differing-pixel counts, and agreement with the recorded encoder metadata.
//! - Embedded marker edge cases (APPn/COM containing 0xFFD9 payload bytes).
//! - Restart marker cadence and interval verification, including MCUs measured per
//!   entropy-coded segment by the independent decoder.
//! - 5 MJPEG variant streams (clean, truncated_last, garbage_between_frames, zero_length, dimension_change).
//! - Manifest integrity and source pixel regeneration match.
//! - Guard test ensuring no production consumer calls fixture generation.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_reference::media_fixture::jpeg::{
    BASE_CHROMA_QUANT, BASE_LUMA_QUANT, brown_luma_96x96, build_jpeg_manifest_json,
    build_mjpeg_manifest_json, compute_sha256_hex, generate_all_jpeg_fixtures,
    generate_all_mjpeg_fixtures, source_pixels,
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
                            // The first-party JPEG *encoder* is production media code (used by
                            // the opt-in synthetic capture facility); the fixture *generator*
                            // surface (scene data, seed manifests, golden fixtures) is not.
                            let encoder_api = line.contains("media_fixture::jpeg::")
                                && ["encode_jpeg", "JpegConfig", "CustomMarker", "Subsampling",
                                    "JpegError"].iter().any(|symbol| line.contains(symbol));
                            if !encoder_api
                                && (line.contains("media_fixture::jpeg")
                                    || (line.contains("media_fixture")
                                        && !line.contains("pub mod media_fixture;")))
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
        let mut saw_eoi = false;

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
                saw_eoi = true;
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
        assert!(saw_eoi, "{}: missing EOI marker", fixture.name);
        assert!(
            bytes.ends_with(&[0xFF, 0xD9]),
            "{}: stream does not end with EOI (0xFF, 0xD9)",
            fixture.name
        );
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
fn test_base_quantization_tables_match_annex_k() -> Result<(), Box<dyn Error>> {
    // ISO/IEC 10918-1 / ITU-T T.81 Annex K Table K.1 (Luminance)
    const EXPECTED_ANNEX_K_LUMA: [u8; 64] = [
        16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69,
        56, 14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81,
        104, 113, 92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
    ];
    // Table K.2 (Chrominance)
    const EXPECTED_ANNEX_K_CHROMA: [u8; 64] = [
        17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99, 24, 26, 56, 99, 99, 99, 99,
        99, 47, 66, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
        99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
    ];
    assert_eq!(
        BASE_LUMA_QUANT, EXPECTED_ANNEX_K_LUMA,
        "BASE_LUMA_QUANT must match ISO/IEC 10918-1 Annex K Table K.1"
    );
    assert_eq!(
        BASE_CHROMA_QUANT, EXPECTED_ANNEX_K_CHROMA,
        "BASE_CHROMA_QUANT must match ISO/IEC 10918-1 Annex K Table K.2"
    );
    assert_eq!(BASE_LUMA_QUANT[0], 16, "BASE_LUMA_QUANT[0] must be 16");
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
fn test_brown_luma_independent_baseline_decode() -> Result<(), Box<dyn Error>> {
    let ref_bytes = brown_luma_96x96();
    let fixtures = generate_all_jpeg_fixtures()?;

    // q100: decode the EMITTED bytes with the test-side decoder (tables parsed from the file).
    let dec_q100 = decode_baseline_jpeg(emitted_jpeg(&fixtures, "brown_luma_q100.jpg")?)?;
    assert_eq!(
        (dec_q100.width, dec_q100.height, dec_q100.comps.len()),
        (96, 96, 1)
    );
    assert_eq!(
        dec_q100.luma_quant, [1u16; 64],
        "q100 DQT parsed by the decoder must be all ones"
    );
    let (psnr_q100, max_err_q100, diff_q100) = dec_error_stats(ref_bytes, &dec_q100.pixels())?;
    println!(
        "independent decode brown_luma_q100: psnr={psnr_q100:.4} max_err={max_err_q100} differing={diff_q100}"
    );
    assert!(
        (58.98..=59.08).contains(&psnr_q100),
        "q100 decoded PSNR must be within 59.03 +/- 0.05 dB, got {psnr_q100:.4}"
    );
    assert_eq!(
        max_err_q100, 1,
        "q100 decoded max error must be exactly 1, got {max_err_q100}"
    );
    assert!(
        (740..=760).contains(&diff_q100),
        "q100 decoded differing pixels must be within [740, 760], got {diff_q100}"
    );

    // qfix (quality 90): decode the EMITTED bytes.
    let dec_qfix = decode_baseline_jpeg(emitted_jpeg(&fixtures, "brown_luma_qfix.jpg")?)?;
    let (psnr_qfix, max_err_qfix, diff_qfix) = dec_error_stats(ref_bytes, &dec_qfix.pixels())?;
    println!(
        "independent decode brown_luma_qfix: psnr={psnr_qfix:.4} max_err={max_err_qfix} differing={diff_qfix}"
    );
    assert!(
        (36.52..=36.62).contains(&psnr_qfix),
        "qfix decoded PSNR must be within 36.57 +/- 0.05 dB, got {psnr_qfix:.4}"
    );
    assert_eq!(
        max_err_qfix, 16,
        "qfix decoded max error must be exactly 16, got {max_err_qfix}"
    );

    // Verify fixtures have recorded these values, and that the recorded encoder metadata
    // agrees with the independent decode of each emitted grey file.
    for f in &fixtures {
        if f.channels == 1 {
            let decoded = decode_baseline_jpeg(&f.file_bytes)?;
            let (dec_psnr, dec_max_err, _) = dec_error_stats(&f.source_bytes, &decoded.pixels())?;
            let recorded = f.encoder_psnr.ok_or("encoder_psnr missing")?;
            assert!(
                (recorded - dec_psnr).abs() <= 0.01,
                "{}: recorded encoder_psnr {recorded:.4} disagrees with independent decode {dec_psnr:.4}",
                f.name
            );
            assert_eq!(
                f.encoder_max_error,
                Some(dec_max_err),
                "{}: recorded encoder_max_error disagrees with independent decode",
                f.name
            );
            assert!(f.encoder_psnr.is_some(), "{}: missing encoder_psnr", f.name);
            assert!(
                f.encoder_max_error.is_some(),
                "{}: missing encoder_max_error",
                f.name
            );
            assert_eq!(
                f.psnr_threshold,
                Some(30.0),
                "{}: missing psnr_threshold 30.0",
                f.name
            );
            let psnr = f.encoder_psnr.ok_or("psnr missing")?;
            match f.name.as_str() {
                "gray_16x16_flat.jpg" => {
                    assert!(
                        psnr >= 999.0,
                        "{}: flat PSNR {psnr:.2} expected >= 999.0",
                        f.name
                    );
                }
                "gray_16x16_gradient.jpg" => {
                    assert!(
                        (51.79..=51.89).contains(&psnr),
                        "{}: PSNR {psnr:.4} outside [51.79, 51.89]",
                        f.name
                    );
                }
                "gray_33x17_checkerboard.jpg" => {
                    assert!(
                        (41.61..=41.71).contains(&psnr),
                        "{}: PSNR {psnr:.4} outside [41.61, 41.71]",
                        f.name
                    );
                }
                "brown_luma_q100.jpg" => {
                    assert!(
                        (58.98..=59.08).contains(&psnr),
                        "{}: PSNR {psnr:.4} outside [58.98, 59.08]",
                        f.name
                    );
                }
                "brown_luma_qfix.jpg" => {
                    assert!(
                        (36.52..=36.62).contains(&psnr),
                        "{}: PSNR {psnr:.4} outside [36.52, 36.62]",
                        f.name
                    );
                }
                other => return Err(format!("unexpected 1-channel fixture: {other}").into()),
            }
        } else {
            assert!(
                f.encoder_psnr.is_none(),
                "{}: colour fixture must have None encoder_psnr",
                f.name
            );
            assert!(
                f.encoder_max_error.is_none(),
                "{}: colour fixture must have None encoder_max_error",
                f.name
            );
            assert!(
                f.psnr_threshold.is_none(),
                "{}: colour fixture must have None psnr_threshold",
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
        .find(|f| f.name == "rgb_64x48_restart_ri5.jpg")
        .ok_or("rgb_64x48_restart_ri5.jpg fixture missing")?;

    let bytes = &f.file_bytes;
    // Total MCUs = (64/16) * (48/16) = 4 * 3 = 12.
    // Check DRI
    let mut dri_found = false;
    let mut sos_offset = 0;
    let mut offset = 2;
    while offset + 4 <= bytes.len() {
        if bytes[offset] == 0xFF && bytes[offset + 1] == 0xDD {
            let ri = ((bytes[offset + 4] as u16) << 8) | (bytes[offset + 5] as u16);
            assert_eq!(ri, 5, "DRI interval must be 5");
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

    // Scan for restart markers in entropy data: 12 MCUs with interval 5 yields RST0, RST1
    let mut restart_markers = Vec::new();
    let mut scan = sos_offset;
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
        "Expected restart markers RST0 at byte offset 736 (after MCU 5) and RST1 at byte offset 865 (after MCU 10)"
    );

    // Independent decode: MCUs are measured per entropy-coded segment from the bitstream
    // (DRI-agnostic), so a wrong restart cadence cannot hide behind a correct DRI value.
    let decoded = decode_baseline_jpeg(bytes)?;
    assert_eq!(decoded.restart_interval, 5, "decoder-parsed DRI must be 5");
    assert_eq!(
        decoded.restart_markers,
        vec![(0xD0, 736), (0xD1, 865)],
        "decoder-observed RSTn markers and file offsets"
    );
    assert_eq!(
        decoded.segment_mcus,
        vec![5, 5, 2],
        "MCUs decoded per entropy-coded segment (SOS..RST0, RST0..RST1, RST1..EOI)"
    );
    let cumulative: Vec<usize> = decoded
        .segment_mcus
        .iter()
        .scan(0usize, |acc, &n| {
            *acc += n;
            Some(*acc)
        })
        .collect();
    assert_eq!(
        cumulative.first(),
        Some(&5),
        "exactly 5 MCUs must be decoded before RST0"
    );
    assert_eq!(
        cumulative.get(1),
        Some(&10),
        "exactly 10 MCUs must be decoded before RST1"
    );

    // Restart only resets DC prediction, so the ri5 picture must decode to the same pixels
    // as the colorbars 4:2:0 fixture (same source, same quality) and meet its fidelity.
    let bars = decode_baseline_jpeg(emitted_jpeg(&fixtures, "rgb_64x48_colorbars_420.jpg")?)?;
    let pixels = decoded.pixels();
    assert_eq!(
        pixels,
        bars.pixels(),
        "restart fixture must decode to the colorbars_420 pixels"
    );
    let (psnr, max_err, _) = dec_error_stats(&f.source_bytes, &pixels)?;
    println!(
        "independent decode rgb_64x48_restart_ri5: segment_mcus={:?} rst={:?} psnr={psnr:.4} max_err={max_err}",
        decoded.segment_mcus, decoded.restart_markers
    );
    assert!(
        (42.39..=42.49).contains(&psnr),
        "restart fixture decoded PSNR {psnr:.4} outside 42.44 +/- 0.05 dB"
    );
    assert_eq!(max_err, 5, "restart fixture decoded max error");
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
                let sos_count = count_subsequences(&m.file_bytes, &[0xFF, 0xDA]);
                let eoi_count = count_subsequences(&m.file_bytes, &[0xFF, 0xD9]);
                assert_eq!(soi_count, 3);
                assert_eq!(
                    sos_count, 3,
                    "Truncated frame must still reach and include SOS header"
                );
                assert_eq!(eoi_count, 2, "Truncated last stream should have 2 EOIs");

                // Verify truncation cut lies strictly inside entropy-coded scan data after SOS header
                let mut found_sos = 0;
                let mut third_sos_pos = None;
                for i in 0..m.file_bytes.len().saturating_sub(4) {
                    if m.file_bytes[i] == 0xFF && m.file_bytes[i + 1] == 0xDA {
                        found_sos += 1;
                        if found_sos == 3 {
                            third_sos_pos = Some(i);
                            break;
                        }
                    }
                }
                let sos_pos = third_sos_pos.ok_or("3rd SOS marker not found")?;
                let sos_header_len = ((m.file_bytes[sos_pos + 2] as usize) << 8)
                    | (m.file_bytes[sos_pos + 3] as usize);
                let entropy_data_start = sos_pos + 2 + sos_header_len;
                assert!(
                    m.file_bytes.len() > entropy_data_start,
                    "Truncation cut at byte {} must lie strictly after SOS header end at {}",
                    m.file_bytes.len(),
                    entropy_data_start
                );
                assert!(
                    m.file_bytes.len() >= entropy_data_start + 10,
                    "Truncated frame must contain at least 10 bytes of entropy-coded scan data"
                );
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
        for fr in &m.frames {
            let fr_src = source_pixels(&fr.source_fixture)?;
            assert_eq!(
                compute_sha256_hex(&fr_src),
                fr.source_pixel_sha256,
                "{}: frame source fixture {} sha mismatch",
                m.name,
                fr.source_fixture
            );
        }
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
fn test_pinned_fixture_sha256_literals() -> Result<(), Box<dyn Error>> {
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
            .ok_or_else(|| format!("fixture {name} missing"))?;
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
            .ok_or_else(|| format!("mjpeg fixture {name} missing"))?;
        assert_eq!(m.file_sha256, expected_sha, "{}: sha mismatch", name);
        assert_eq!(compute_sha256_hex(&m.file_bytes), expected_sha);
    }

    Ok(())
}

#[test]
fn test_mjpeg_manifest_frame_spans_and_hashes() -> Result<(), Box<dyn Error>> {
    let mjpegs = generate_all_mjpeg_fixtures()?;
    for m in &mjpegs {
        for fr in &m.frames {
            assert!(
                fr.offset + fr.length <= m.file_bytes.len(),
                "{}: frame {} span [{}, {}) exceeds file length {}",
                m.name,
                fr.index,
                fr.offset,
                fr.offset + fr.length,
                m.file_bytes.len()
            );
            let frame_slice = &m.file_bytes[fr.offset..fr.offset + fr.length];
            assert_eq!(
                compute_sha256_hex(frame_slice),
                fr.frame_sha256,
                "{}: frame {} SHA-256 mismatch",
                m.name,
                fr.index
            );
            if fr.length >= 4 && !fr.source_fixture.contains("truncated") {
                assert_eq!(
                    &frame_slice[0..2],
                    &[0xFF, 0xD8],
                    "{}: frame {} missing SOI",
                    m.name,
                    fr.index
                );
                assert_eq!(
                    &frame_slice[frame_slice.len() - 2..],
                    &[0xFF, 0xD9],
                    "{}: frame {} missing EOI",
                    m.name,
                    fr.index
                );
            }
        }
    }
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

    let jpeg_manifest_path = jpeg_dir.join("fixture_manifest.json");
    assert!(
        jpeg_manifest_path.exists(),
        "JPEG fixture_manifest.json missing: {}",
        jpeg_manifest_path.display()
    );
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
    let manifest_disk = fs::read_to_string(&jpeg_manifest_path)?;
    let manifest_gen = build_jpeg_manifest_json(&jpegs);
    assert_eq!(
        manifest_disk, manifest_gen,
        "JPEG manifest differs from generator"
    );

    let mjpeg_manifest_path = mjpeg_dir.join("fixture_manifest.json");
    assert!(
        mjpeg_manifest_path.exists(),
        "MJPEG fixture_manifest.json missing: {}",
        mjpeg_manifest_path.display()
    );
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
    let manifest_disk = fs::read_to_string(&mjpeg_manifest_path)?;
    let manifest_gen = build_mjpeg_manifest_json(&mjpegs);
    assert_eq!(
        manifest_disk, manifest_gen,
        "MJPEG manifest differs from generator"
    );

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

// ---------------------------------------------------------------------------
// Test-side independent baseline JPEG decoder (ITU-T T.81 Annex F, sequential
// DCT, Huffman, 8-bit). Every quantization and Huffman table is parsed from the
// emitted bytes; nothing is shared with the encoder under test (no tables, no
// basis matrix, no helper functions). Restricted to what the fixtures use:
// SOF0, one interleaved scan (grey 1x1 or 3-component YCbCr), optional DRI/RSTn.
// Entropy-coded segments are walked independently of DRI: each segment between
// SOS/RSTn/EOI is decoded until only 1-padding (< 8 bits) remains, so the number
// of MCUs per segment is measured from the bitstream, not assumed.
// ---------------------------------------------------------------------------

/// Zigzag scan position -> natural (row-major) coefficient index (T.81 Figure A.6).
const DEC_ZIGZAG: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

/// Canonical Huffman decode table (T.81 F.2.2.3 MAXCODE/MINCODE/VALPTR).
#[derive(Clone)]
struct DecHuffman {
    maxcode: [i32; 17],
    mincode: [i32; 17],
    valptr: [usize; 17],
    vals: Vec<u8>,
}

impl DecHuffman {
    fn from_spec(bits: &[u8], vals: &[u8]) -> Self {
        let mut maxcode = [-1i32; 17];
        let mut mincode = [0i32; 17];
        let mut valptr = [0usize; 17];
        let mut code = 0i32;
        let mut k = 0usize;
        for len in 1..=16usize {
            let n = usize::from(bits[len - 1]);
            if n > 0 {
                valptr[len] = k;
                mincode[len] = code;
                code += n as i32;
                k += n;
                maxcode[len] = code - 1;
            }
            code <<= 1;
        }
        Self {
            maxcode,
            mincode,
            valptr,
            vals: vals.to_vec(),
        }
    }
}

#[derive(Clone, Copy)]
struct DecComponent {
    id: u8,
    h: usize,
    v: usize,
    tq: usize,
}

/// Result of decoding one baseline JPEG from its bytes.
struct DecodedJpeg {
    width: usize,
    height: usize,
    comps: Vec<DecComponent>,
    /// Sample planes (one per component), each `plane_w[i]` samples wide.
    planes: Vec<Vec<u8>>,
    plane_w: Vec<usize>,
    hmax: usize,
    vmax: usize,
    /// DRI value parsed from the file (0 when absent).
    restart_interval: usize,
    /// Luma (table 0) quantization table parsed from DQT, natural order.
    luma_quant: [u16; 64],
    /// MCUs measured in each entropy-coded segment, in stream order.
    segment_mcus: Vec<usize>,
    /// (marker byte, file offset) of every RSTn met in the entropy-coded data.
    restart_markers: Vec<(u8, usize)>,
}

struct DecBits {
    data: Vec<u8>,
    pos: usize,
}

impl DecBits {
    fn remaining(&self) -> usize {
        self.data.len() * 8 - self.pos
    }

    /// True when nothing, or only fewer than 8 one-bits (T.81 F.1.2.3 padding), remain.
    /// Every Annex K DC code contains a 0 bit, so an all-ones tail cannot start an MCU.
    fn only_padding_left(&self) -> bool {
        let rem = self.remaining();
        if rem == 0 {
            return true;
        }
        if rem >= 8 {
            return false;
        }
        (self.pos..self.data.len() * 8).all(|p| (self.data[p / 8] >> (7 - p % 8)) & 1 == 1)
    }

    fn bit(&mut self) -> Result<i32, String> {
        if self.pos >= self.data.len() * 8 {
            return Err(format!(
                "entropy-coded segment exhausted at bit {}",
                self.pos
            ));
        }
        let b = (self.data[self.pos / 8] >> (7 - self.pos % 8)) & 1;
        self.pos += 1;
        Ok(i32::from(b))
    }

    fn receive_extend(&mut self, s: u8) -> Result<i32, String> {
        if s == 0 {
            return Ok(0);
        }
        if s > 15 {
            return Err(format!("magnitude category {s} out of range"));
        }
        let mut v = 0i32;
        for _ in 0..s {
            v = (v << 1) | self.bit()?;
        }
        if v < (1 << (s - 1)) {
            v -= (1 << s) - 1;
        }
        Ok(v)
    }

    fn huff(&mut self, t: &DecHuffman) -> Result<u8, String> {
        let mut code = self.bit()?;
        let mut len = 1usize;
        while code > t.maxcode[len] {
            len += 1;
            if len > 16 {
                return Err("invalid Huffman code".to_string());
            }
            code = (code << 1) | self.bit()?;
        }
        let idx = t.valptr[len] + (code - t.mincode[len]) as usize;
        t.vals
            .get(idx)
            .copied()
            .ok_or_else(|| "Huffman value index out of range".to_string())
    }
}

/// Float separable IDCT (T.81 A.3.3), level shift +128, round half up, clamp.
fn dec_float_idct(coef: &[f64; 64]) -> [u8; 64] {
    let mut cos_t = [[0.0f64; 8]; 8];
    for (x, row) in cos_t.iter_mut().enumerate() {
        for (u, c) in row.iter_mut().enumerate() {
            *c = (((2 * x + 1) * u) as f64 * std::f64::consts::PI / 16.0).cos();
        }
    }
    let cu = |u: usize| {
        if u == 0 {
            std::f64::consts::FRAC_1_SQRT_2
        } else {
            1.0
        }
    };
    let mut tmp = [[0.0f64; 8]; 8];
    for (y, trow) in tmp.iter_mut().enumerate() {
        for (u, t) in trow.iter_mut().enumerate() {
            *t = (0..8)
                .map(|v| cu(v) * coef[v * 8 + u] * cos_t[y][v])
                .sum::<f64>();
        }
    }
    let mut out = [0u8; 64];
    for y in 0..8 {
        for x in 0..8 {
            let s = (0..8).map(|u| cu(u) * tmp[y][u] * cos_t[x][u]).sum::<f64>() / 4.0;
            out[y * 8 + x] = (s + 128.0 + 0.5).floor().clamp(0.0, 255.0) as u8;
        }
    }
    out
}

fn dec_u16(bytes: &[u8], at: usize) -> Result<usize, String> {
    match (bytes.get(at), bytes.get(at + 1)) {
        (Some(&hi), Some(&lo)) => Ok((usize::from(hi) << 8) | usize::from(lo)),
        _ => Err(format!("truncated 16-bit field at {at}")),
    }
}

/// Decodes a baseline JPEG from its bytes. Returns `Err` on anything outside the
/// supported subset or on any structural/bitstream inconsistency.
fn decode_baseline_jpeg(bytes: &[u8]) -> Result<DecodedJpeg, String> {
    if bytes.get(0..2) != Some(&[0xFF, 0xD8][..]) {
        return Err("missing SOI".to_string());
    }
    let mut quant: [Option<[u16; 64]>; 4] = [None; 4];
    let mut dc_tables: [Option<DecHuffman>; 4] = [None, None, None, None];
    let mut ac_tables: [Option<DecHuffman>; 4] = [None, None, None, None];
    let mut frame: Option<(usize, usize, Vec<DecComponent>)> = None;
    let mut restart_interval = 0usize;
    let mut p = 2usize;
    loop {
        if bytes.get(p) != Some(&0xFF) {
            return Err(format!("expected marker at {p}"));
        }
        let marker = *bytes.get(p + 1).ok_or("truncated marker")?;
        if marker == 0xD9 {
            return Err("EOI before SOS".to_string());
        }
        let len = dec_u16(bytes, p + 2)?;
        let payload = bytes
            .get(p + 4..p + 2 + len)
            .ok_or_else(|| format!("segment 0x{marker:02X} at {p} truncated"))?;
        match marker {
            0xDB => {
                let mut i = 0;
                while i < payload.len() {
                    let (pq, tq) = (payload[i] >> 4, usize::from(payload[i] & 15));
                    if pq != 0 || tq > 3 {
                        return Err(format!("unsupported DQT pq={pq} tq={tq}"));
                    }
                    let raw = payload.get(i + 1..i + 65).ok_or("DQT truncated")?;
                    let mut t = [0u16; 64];
                    for (k, &q) in raw.iter().enumerate() {
                        t[DEC_ZIGZAG[k]] = u16::from(q);
                    }
                    quant[tq] = Some(t);
                    i += 65;
                }
            }
            0xC4 => {
                let mut i = 0;
                while i < payload.len() {
                    let (tc, th) = (payload[i] >> 4, usize::from(payload[i] & 15));
                    let bits = payload.get(i + 1..i + 17).ok_or("DHT truncated")?;
                    let n: usize = bits.iter().map(|&b| usize::from(b)).sum();
                    let vals = payload.get(i + 17..i + 17 + n).ok_or("DHT truncated")?;
                    let table = DecHuffman::from_spec(bits, vals);
                    match (tc, th) {
                        (0, 0..=3) => dc_tables[th] = Some(table),
                        (1, 0..=3) => ac_tables[th] = Some(table),
                        _ => return Err(format!("unsupported DHT tc={tc} th={th}")),
                    }
                    i += 17 + n;
                }
            }
            0xC0 => {
                if payload.first() != Some(&8) {
                    return Err("sample precision is not 8".to_string());
                }
                let height = dec_u16(payload, 1)?;
                let width = dec_u16(payload, 3)?;
                let nc = usize::from(*payload.get(5).ok_or("SOF0 truncated")?);
                let mut comps = Vec::new();
                for j in 0..nc {
                    let c = payload.get(6 + 3 * j..9 + 3 * j).ok_or("SOF0 truncated")?;
                    comps.push(DecComponent {
                        id: c[0],
                        h: usize::from(c[1] >> 4),
                        v: usize::from(c[1] & 15),
                        tq: usize::from(c[2] & 3),
                    });
                }
                frame = Some((width, height, comps));
            }
            0xC1..=0xCF if marker != 0xC4 && marker != 0xC8 && marker != 0xCC => {
                return Err(format!("non-baseline SOF 0x{marker:02X}"));
            }
            0xDD => restart_interval = dec_u16(payload, 0)?,
            0xDA => {
                let (width, height, comps) = frame.take().ok_or("SOS before SOF0")?;
                let ns = usize::from(*payload.first().ok_or("SOS truncated")?);
                if ns != comps.len() || !matches!(ns, 1 | 3) {
                    return Err(format!("unsupported scan: ns={ns} nc={}", comps.len()));
                }
                let tail = payload.get(1 + 2 * ns..4 + 2 * ns).ok_or("SOS truncated")?;
                if tail != [0, 63, 0] {
                    return Err("not a baseline sequential scan".to_string());
                }
                let mut scan = Vec::new();
                for j in 0..ns {
                    let cid = payload[1 + 2 * j];
                    let sel = payload[2 + 2 * j];
                    let ci = comps
                        .iter()
                        .position(|c| c.id == cid)
                        .ok_or("SOS names unknown component")?;
                    let dc = dc_tables[usize::from(sel >> 4) & 3]
                        .clone()
                        .ok_or("missing DC table")?;
                    let ac = ac_tables[usize::from(sel & 15) & 3]
                        .clone()
                        .ok_or("missing AC table")?;
                    let q = quant[comps[ci].tq].ok_or("missing DQT")?;
                    scan.push((ci, dc, ac, q));
                }
                let luma_quant = quant[0].ok_or("missing luma DQT")?;
                return decode_scan(
                    bytes,
                    p + 2 + len,
                    (width, height, comps),
                    &scan,
                    restart_interval,
                    luma_quant,
                );
            }
            _ => {}
        }
        p += 2 + len;
    }
}

type DecScanComponent = (usize, DecHuffman, DecHuffman, [u16; 64]);

fn decode_scan(
    bytes: &[u8],
    scan_start: usize,
    (width, height, comps): (usize, usize, Vec<DecComponent>),
    scan: &[DecScanComponent],
    restart_interval: usize,
    luma_quant: [u16; 64],
) -> Result<DecodedJpeg, String> {
    let hmax = comps.iter().map(|c| c.h).max().ok_or("no components")?;
    let vmax = comps.iter().map(|c| c.v).max().ok_or("no components")?;
    if comps.len() == 1 && (hmax, vmax) != (1, 1) {
        return Err("single-component scan must be 1x1 sampled".to_string());
    }
    let mcux = width.div_ceil(8 * hmax);
    let mcuy = height.div_ceil(8 * vmax);
    let total_mcus = mcux * mcuy;
    let plane_w: Vec<usize> = comps.iter().map(|c| mcux * c.h * 8).collect();
    let mut planes: Vec<Vec<u8>> = comps
        .iter()
        .map(|c| vec![0u8; mcux * c.h * 8 * mcuy * c.v * 8])
        .collect();

    // Split the entropy-coded data into segments at RSTn / EOI, unstuffing FF00.
    let mut segments: Vec<Vec<u8>> = vec![Vec::new()];
    let mut restart_markers = Vec::new();
    let mut p = scan_start;
    loop {
        let b = *bytes
            .get(p)
            .ok_or("entropy-coded data truncated before EOI")?;
        if b != 0xFF {
            segments.last_mut().ok_or("no segment")?.push(b);
            p += 1;
            continue;
        }
        let next = *bytes.get(p + 1).ok_or("trailing 0xFF in entropy data")?;
        match next {
            0x00 => {
                segments.last_mut().ok_or("no segment")?.push(0xFF);
                p += 2;
            }
            0xD0..=0xD7 => {
                restart_markers.push((next, p));
                segments.push(Vec::new());
                p += 2;
            }
            0xD9 => {
                if p + 2 != bytes.len() {
                    return Err(format!("EOI at {p} is not the end of the file"));
                }
                break;
            }
            other => {
                return Err(format!("marker 0xFF{other:02X} inside entropy data at {p}"));
            }
        }
    }

    let mut mcu = 0usize;
    let mut segment_mcus = Vec::new();
    for (seg_idx, seg) in segments.into_iter().enumerate() {
        let mut bits = DecBits { data: seg, pos: 0 };
        let mut preds = vec![0i32; comps.len()];
        let mut in_segment = 0usize;
        while !bits.only_padding_left() {
            if mcu >= total_mcus {
                return Err(format!(
                    "segment {seg_idx} carries more than {total_mcus} MCUs"
                ));
            }
            let (my, mx) = (mcu / mcux, mcu % mcux);
            for (ci, dc, ac, q) in scan {
                let c = comps[*ci];
                for bv in 0..c.v {
                    for bh in 0..c.h {
                        let mut coef = [0.0f64; 64];
                        let t = bits.huff(dc)?;
                        preds[*ci] += bits.receive_extend(t)?;
                        coef[0] = f64::from(preds[*ci]) * f64::from(q[0]);
                        let mut k = 1usize;
                        while k < 64 {
                            let rs = bits.huff(ac)?;
                            let (r, s) = (usize::from(rs >> 4), rs & 15);
                            if s == 0 {
                                if r == 15 {
                                    k += 16;
                                    continue;
                                }
                                break;
                            }
                            k += r;
                            if k > 63 {
                                return Err("AC coefficient index overflow".to_string());
                            }
                            let nat = DEC_ZIGZAG[k];
                            coef[nat] = f64::from(bits.receive_extend(s)?) * f64::from(q[nat]);
                            k += 1;
                        }
                        let block = dec_float_idct(&coef);
                        let by = (my * c.v + bv) * 8;
                        let bx = (mx * c.h + bh) * 8;
                        for yy in 0..8 {
                            let row = (by + yy) * plane_w[*ci] + bx;
                            planes[*ci][row..row + 8].copy_from_slice(&block[yy * 8..yy * 8 + 8]);
                        }
                    }
                }
            }
            mcu += 1;
            in_segment += 1;
        }
        segment_mcus.push(in_segment);
    }
    if mcu != total_mcus {
        return Err(format!("decoded {mcu} MCUs, frame needs {total_mcus}"));
    }
    Ok(DecodedJpeg {
        width,
        height,
        comps,
        planes,
        plane_w,
        hmax,
        vmax,
        restart_interval,
        luma_quant,
        segment_mcus,
        restart_markers,
    })
}

impl DecodedJpeg {
    /// Cropped output pixels: grey bytes, or interleaved RGB (JFIF YCbCr, nearest chroma).
    fn pixels(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for y in 0..self.height {
            for x in 0..self.width {
                let sample = |ci: usize| {
                    let c = self.comps[ci];
                    let sy = y * c.v / self.vmax;
                    let sx = x * c.h / self.hmax;
                    f64::from(self.planes[ci][sy * self.plane_w[ci] + sx])
                };
                if self.comps.len() == 1 {
                    out.push(sample(0) as u8);
                } else {
                    let (yv, cb, cr) = (sample(0), sample(1) - 128.0, sample(2) - 128.0);
                    for v in [
                        yv + 1.402 * cr,
                        yv - 0.344_136 * cb - 0.714_136 * cr,
                        yv + 1.772 * cb,
                    ] {
                        out.push((v + 0.5).floor().clamp(0.0, 255.0) as u8);
                    }
                }
            }
        }
        out
    }
}

/// Emitted file bytes of the named generated JPEG fixture.
fn emitted_jpeg<'a>(
    fixtures: &'a [fss_reference::media_fixture::jpeg::GeneratedJpegFixture],
    name: &str,
) -> Result<&'a [u8], String> {
    fixtures
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.file_bytes.as_slice())
        .ok_or_else(|| format!("{name} fixture missing"))
}

/// (PSNR dB, max absolute error, differing sample count); PSNR is 999.0 for identical inputs.
fn dec_error_stats(source: &[u8], decoded: &[u8]) -> Result<(f64, u32, usize), String> {
    if source.len() != decoded.len() || source.is_empty() {
        return Err(format!(
            "length mismatch: source {} decoded {}",
            source.len(),
            decoded.len()
        ));
    }
    let mut sum_sq = 0.0f64;
    let mut max_err = 0u32;
    let mut ndiff = 0usize;
    for (&a, &b) in source.iter().zip(decoded) {
        let d = u32::from(a.abs_diff(b));
        sum_sq += f64::from(d * d);
        max_err = max_err.max(d);
        ndiff += usize::from(d != 0);
    }
    let mse = sum_sq / source.len() as f64;
    let psnr = if mse <= 1e-10 {
        999.0
    } else {
        10.0 * (255.0 * 255.0 / mse).log10()
    };
    Ok((psnr, max_err, ndiff))
}

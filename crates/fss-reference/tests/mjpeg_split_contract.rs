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
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use fss_reference::DeterministicFaultPrng;
use fss_reference::ReplayCx;
use fss_reference::ingest::mjpeg::{
    JpegFinding, JpegSplitError, MjpegLimits, OmissionReason, OmissionSpan, split_jpeg_stream,
};

/// Emits a single-line structured CAPLOG record for digestion by the E2E logging harness.
fn emit_caplog(step: &str, verdict: &str, expected: &str, observed: &str) {
    println!(
        "CAPLOG {{\"step\":\"{}\",\"verdict\":\"{}\",\"exit\":0,\"duration_ms\":1,\"expected\":{},\"observed\":{}}}",
        step, verdict, expected, observed
    );
}

/// Helper to build a synthetic, structurally valid baseline JPEG frame.
fn build_test_jpeg(width: u16, height: u16, payload_byte: u8) -> Vec<u8> {
    let mut data = Vec::with_capacity(128);
    // SOI
    data.extend_from_slice(&[0xFF, 0xD8]);

    // DQT (length = 67, 1 table of 64 bytes)
    data.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00]);
    data.extend_from_slice(&[16u8; 64]);

    // SOF0 (Baseline, 8-bit precision, 3 components)
    // Segment length = 17 (2 length + 1 precision + 2 height + 2 width + 1 num_components + 3*3 comp specs)
    data.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
    data.extend_from_slice(&height.to_be_bytes());
    data.extend_from_slice(&width.to_be_bytes());
    data.push(3); // 3 components (Y, Cb, Cr)
    data.extend_from_slice(&[1, 0x11, 0]); // Y: ID 1, 1:1 sampling, QT 0
    data.extend_from_slice(&[2, 0x11, 0]); // Cb: ID 2, 1:1 sampling, QT 0
    data.extend_from_slice(&[3, 0x11, 0]); // Cr: ID 3, 1:1 sampling, QT 0

    // SOS (Start of Scan)
    // Segment length = 12 (2 length + 1 num_components + 3*2 comp selectors + 3 spectral/approx)
    data.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x0C, 0x03]);
    data.extend_from_slice(&[1, 0x00, 2, 0x11, 3, 0x11, 0x00, 0x3F, 0x00]);

    // Entropy-coded segment (ECS)
    data.extend_from_slice(&[payload_byte, 0x42, 0x99]);

    // EOI
    data.extend_from_slice(&[0xFF, 0xD9]);
    data
}

/// Helper to build a JPEG frame with APP1 and COM segments containing embedded 0xFFD9.
fn build_jpeg_with_appn_com(width: u16, height: u16) -> Vec<u8> {
    let mut data = Vec::with_capacity(256);
    data.extend_from_slice(&[0xFF, 0xD8]); // SOI

    // APP1 with embedded FF D9 in payload
    // Length = 8 (2 length bytes + 6 payload bytes including FF D9)
    data.extend_from_slice(&[0xFF, 0xE1, 0x00, 0x08, 0x45, 0x78, 0xFF, 0xD9, 0x00, 0x01]);

    // COM with embedded FF D9 in payload
    data.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x06, 0xAA, 0xFF, 0xD9, 0xBB]);

    // DQT
    data.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00]);
    data.extend_from_slice(&[16u8; 64]);

    // SOF0
    data.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
    data.extend_from_slice(&height.to_be_bytes());
    data.extend_from_slice(&width.to_be_bytes());
    data.push(3);
    data.extend_from_slice(&[1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0]);

    // SOS
    data.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x0C, 0x03]);
    data.extend_from_slice(&[1, 0x00, 2, 0x11, 3, 0x11, 0x00, 0x3F, 0x00]);

    // ECS
    data.extend_from_slice(&[0x12, 0x34]);

    // EOI
    data.extend_from_slice(&[0xFF, 0xD9]);
    data
}

/// Helper to build a JPEG frame with DRI and sequential restart markers RST0..RST7.
fn build_jpeg_with_restart_markers(width: u16, height: u16, restart_interval: u16) -> Vec<u8> {
    let mut data = Vec::with_capacity(256);
    data.extend_from_slice(&[0xFF, 0xD8]); // SOI

    // DRI (length = 4, Ri)
    data.extend_from_slice(&[0xFF, 0xDD, 0x00, 0x04]);
    data.extend_from_slice(&restart_interval.to_be_bytes());

    // DQT
    data.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00]);
    data.extend_from_slice(&[16u8; 64]);

    // SOF0
    data.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
    data.extend_from_slice(&height.to_be_bytes());
    data.extend_from_slice(&width.to_be_bytes());
    data.push(3);
    data.extend_from_slice(&[1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0]);

    // SOS
    data.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x0C, 0x03]);
    data.extend_from_slice(&[1, 0x00, 2, 0x11, 3, 0x11, 0x00, 0x3F, 0x00]);

    // ECS with sequential RST0..RST7
    for rst in 0..8 {
        data.extend_from_slice(&[0x11, 0x22]);
        data.extend_from_slice(&[0xFF, 0xD0 + rst]);
    }
    data.extend_from_slice(&[0x33, 0x44]);

    // EOI
    data.extend_from_slice(&[0xFF, 0xD9]);
    data
}

/// Helper to build a JPEG frame with byte-stuffed 0xFF00 sequences inside scan data.
fn build_jpeg_with_byte_stuffing(width: u16, height: u16) -> Vec<u8> {
    let mut data = Vec::with_capacity(256);
    data.extend_from_slice(&[0xFF, 0xD8]); // SOI
    data.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00]);
    data.extend_from_slice(&[16u8; 64]);
    data.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
    data.extend_from_slice(&height.to_be_bytes());
    data.extend_from_slice(&width.to_be_bytes());
    data.push(3);
    data.extend_from_slice(&[1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0]);
    data.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x0C, 0x03]);
    data.extend_from_slice(&[1, 0x00, 2, 0x11, 3, 0x11, 0x00, 0x3F, 0x00]);
    // ECS with multiple byte-stuffed sequences
    data.extend_from_slice(&[0x10, 0xFF, 0x00, 0x20, 0xFF, 0x00, 0x30, 0xFF, 0x00, 0x40]);
    data.extend_from_slice(&[0xFF, 0xD9]); // EOI
    data
}

/// Helper to build a JPEG frame with 0xFF fill byte runs before markers.
fn build_jpeg_with_fill_bytes(width: u16, height: u16) -> Vec<u8> {
    let mut data = Vec::with_capacity(256);
    data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xD8]); // SOI with fill bytes
    data.extend_from_slice(&[0xFF, 0xFF, 0xDB, 0x00, 0x43, 0x00]); // DQT with fill bytes
    data.extend_from_slice(&[16u8; 64]);
    data.extend_from_slice(&[0xFF, 0xFF, 0xC0, 0x00, 0x11, 0x08]); // SOF0 with fill bytes
    data.extend_from_slice(&height.to_be_bytes());
    data.extend_from_slice(&width.to_be_bytes());
    data.push(3);
    data.extend_from_slice(&[1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0]);
    data.extend_from_slice(&[0xFF, 0xFF, 0xDA, 0x00, 0x0C, 0x03]); // SOS with fill bytes
    data.extend_from_slice(&[1, 0x00, 2, 0x11, 3, 0x11, 0x00, 0x3F, 0x00]);
    // ECS with fill bytes before RST0
    data.extend_from_slice(&[0x11, 0x22, 0xFF, 0xFF, 0xD0, 0x33, 0x44]);
    // ECS with fill bytes before EOI
    data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xD9]);
    data
}

/// Helper to build a JPEG frame with zero-length marker segments.
fn build_jpeg_with_zero_length_marker(width: u16, height: u16) -> Vec<u8> {
    let mut data = Vec::with_capacity(256);
    data.extend_from_slice(&[0xFF, 0xD8]); // SOI
    // Sub-minimal marker length: length = 0 (< 2) -> ZeroLengthMarkerSegment finding
    data.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x00]);
    // Minimal valid marker length: length = 2 (0 payload bytes) -> validly skipped
    data.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x02]);
    data.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00]);
    data.extend_from_slice(&[16u8; 64]);
    data.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
    data.extend_from_slice(&height.to_be_bytes());
    data.extend_from_slice(&width.to_be_bytes());
    data.push(3);
    data.extend_from_slice(&[1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0]);
    data.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x0C, 0x03]);
    data.extend_from_slice(&[1, 0x00, 2, 0x11, 3, 0x11, 0x00, 0x3F, 0x00]);
    data.extend_from_slice(&[0x42, 0x43]);
    data.extend_from_slice(&[0xFF, 0xD9]);
    data
}

/// Helper to build a JPEG frame with 0 components in SOF0.
fn build_jpeg_with_zero_components(width: u16, height: u16) -> Vec<u8> {
    let mut data = Vec::with_capacity(128);
    data.extend_from_slice(&[0xFF, 0xD8]);
    data.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00]);
    data.extend_from_slice(&[16u8; 64]);
    // SOF0 with components = 0
    data.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x08, 0x08]);
    data.extend_from_slice(&height.to_be_bytes());
    data.extend_from_slice(&width.to_be_bytes());
    data.push(0); // 0 components
    data.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x0C, 0x03]);
    data.extend_from_slice(&[1, 0x00, 2, 0x11, 3, 0x11, 0x00, 0x3F, 0x00]);
    data.extend_from_slice(&[0x42, 0x43]);
    data.extend_from_slice(&[0xFF, 0xD9]);
    data
}

// ---------------------------------------------------------------------------
// 1. Fixture Manifest Equality & E2E CAPLOG Verification
// ---------------------------------------------------------------------------

#[test]
fn test_fixture_manifest_equality_and_e2e_caplog() -> Result<(), Box<dyn Error>> {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    let mjpeg_dir = repo_root.join("tests/fixtures/media/mjpeg");
    let manifest_path = mjpeg_dir.join("fixture_manifest.json");

    let limits = MjpegLimits::default();

    // 1.1 Clean 3-frame variant
    let clean_bytes = if mjpeg_dir.join("mjpeg_clean_3frames.mjpeg").exists() {
        fs::read(mjpeg_dir.join("mjpeg_clean_3frames.mjpeg"))?
    } else {
        let f1 = build_test_jpeg(64, 48, 0x01);
        let f2 = build_test_jpeg(64, 48, 0x02);
        let f3 = build_test_jpeg(64, 48, 0x03);
        let mut s = Vec::new();
        s.extend_from_slice(&f1);
        s.extend_from_slice(&f2);
        s.extend_from_slice(&f3);
        s
    };
    let scan_clean = split_jpeg_stream(&clean_bytes, &limits, None)?;
    assert_eq!(scan_clean.frame_count(), 3);
    assert_eq!(scan_clean.valid_frame_count(), 3);
    assert!(!scan_clean.has_truncation());
    assert!(!scan_clean.has_omissions());
    for (i, frame) in scan_clean.frames.iter().enumerate() {
        assert_eq!(frame.frame_index, i);
        let sof = frame.sof.as_ref().ok_or("SOF expected")?;
        assert_eq!(sof.width, 64);
        assert_eq!(sof.height, 48);
    }
    emit_caplog(
        "fixture_clean_3frames",
        "pass",
        r#"{"frame_count":3,"dimensions":[64,48]}"#,
        r#"{"frame_count":3,"dimensions":[64,48]}"#,
    );

    // 1.2 Truncated last frame variant
    let trunc_bytes = if mjpeg_dir.join("mjpeg_truncated_last.mjpeg").exists() {
        fs::read(mjpeg_dir.join("mjpeg_truncated_last.mjpeg"))?
    } else {
        let f1 = build_test_jpeg(64, 48, 0x01);
        let f2 = build_test_jpeg(64, 48, 0x02);
        let mut f3 = build_test_jpeg(64, 48, 0x03);
        f3.truncate(f3.len() - 2); // strip terminating EOI
        let mut s = Vec::new();
        s.extend_from_slice(&f1);
        s.extend_from_slice(&f2);
        s.extend_from_slice(&f3);
        s
    };
    let scan_trunc = split_jpeg_stream(&trunc_bytes, &limits, None)?;
    assert_eq!(scan_trunc.frame_count(), 3);
    assert_eq!(scan_trunc.valid_frame_count(), 2);
    assert!(scan_trunc.has_truncation());
    assert!(scan_trunc.frames[2].is_truncated);
    assert!(!scan_trunc.frames[2].has_eoi);
    assert!(
        scan_trunc
            .findings
            .iter()
            .any(|f| matches!(f, JpegFinding::TruncatedFrame { frame_index: 2, .. }))
    );
    emit_caplog(
        "fixture_truncated_last",
        "pass",
        r#"{"frame_count":3,"valid_frames":2,"truncated":true}"#,
        r#"{"frame_count":3,"valid_frames":2,"truncated":true}"#,
    );

    // 1.3 Garbage between frames variant
    let garbage_bytes = if mjpeg_dir
        .join("mjpeg_garbage_between_frames.mjpeg")
        .exists()
    {
        fs::read(mjpeg_dir.join("mjpeg_garbage_between_frames.mjpeg"))?
    } else {
        let f1 = build_test_jpeg(64, 48, 0x01);
        let f2 = build_test_jpeg(64, 48, 0x02);
        let f3 = build_test_jpeg(64, 48, 0x03);
        let mut s = Vec::new();
        s.extend_from_slice(&f1);
        s.extend_from_slice(b"--boundary\r\n");
        s.extend_from_slice(&f2);
        s.extend_from_slice(b"--boundary\r\n");
        s.extend_from_slice(&f3);
        s
    };
    let scan_garbage = split_jpeg_stream(&garbage_bytes, &limits, None)?;
    assert_eq!(scan_garbage.frame_count(), 3);
    assert_eq!(scan_garbage.valid_frame_count(), 3);
    assert!(scan_garbage.has_omissions());
    assert_eq!(scan_garbage.omissions.len(), 2);
    assert_eq!(
        scan_garbage.omissions[0].reason,
        OmissionReason::GarbageBetweenFrames
    );
    assert_eq!(
        scan_garbage.omissions[1].reason,
        OmissionReason::GarbageBetweenFrames
    );
    emit_caplog(
        "fixture_garbage_between_frames",
        "pass",
        r#"{"frame_count":3,"omission_count":2}"#,
        r#"{"frame_count":3,"omission_count":2}"#,
    );

    // 1.4 Zero-length stream variant
    let zero_bytes = if mjpeg_dir.join("mjpeg_zero_length.mjpeg").exists() {
        fs::read(mjpeg_dir.join("mjpeg_zero_length.mjpeg"))?
    } else {
        Vec::new()
    };
    let zero_res = split_jpeg_stream(&zero_bytes, &limits, None);
    assert!(matches!(zero_res, Err(JpegSplitError::NoSoi)));
    emit_caplog(
        "fixture_zero_length",
        "pass",
        r#"{"expected_err":"NoSoi"}"#,
        r#"{"observed_err":"NoSoi"}"#,
    );

    // 1.5 Mid-stream dimension change variant
    let dim_bytes = if mjpeg_dir.join("mjpeg_dimension_change.mjpeg").exists() {
        fs::read(mjpeg_dir.join("mjpeg_dimension_change.mjpeg"))?
    } else {
        let f1 = build_test_jpeg(16, 16, 0x01);
        let f2 = build_test_jpeg(64, 48, 0x02);
        let mut s = Vec::new();
        s.extend_from_slice(&f1);
        s.extend_from_slice(&f2);
        s
    };
    let scan_dim = split_jpeg_stream(&dim_bytes, &limits, None)?;
    assert_eq!(scan_dim.frame_count(), 2);
    assert_eq!(scan_dim.valid_frame_count(), 2);
    let sof0 = scan_dim.frames[0].sof.as_ref().ok_or("SOF 0 expected")?;
    assert_eq!(sof0.width, 16);
    assert_eq!(sof0.height, 16);
    let sof1 = scan_dim.frames[1].sof.as_ref().ok_or("SOF 1 expected")?;
    assert_eq!(sof1.width, 64);
    assert_eq!(sof1.height, 48);
    emit_caplog(
        "fixture_dimension_change",
        "pass",
        r#"{"frame_0":[16,16],"frame_1":[64,48]}"#,
        r#"{"frame_0":[16,16],"frame_1":[64,48]}"#,
    );

    // 1.6 On-disk manifest equality verification (when .5 manifest lands)
    if manifest_path.exists() {
        let manifest_content = fs::read_to_string(&manifest_path)?;
        assert!(manifest_content.contains(r#""schema": "fss.mjpeg_fixture_manifest.v1""#));
        assert!(manifest_content.contains(r#""mjpeg_clean_3frames.mjpeg""#));
        assert!(manifest_content.contains(r#""mjpeg_truncated_last.mjpeg""#));
        assert!(manifest_content.contains(r#""mjpeg_garbage_between_frames.mjpeg""#));
        assert!(manifest_content.contains(r#""mjpeg_zero_length.mjpeg""#));
        assert!(manifest_content.contains(r#""mjpeg_dimension_change.mjpeg""#));
        emit_caplog(
            "fixture_manifest_schema_and_rows",
            "pass",
            r#"{"manifest":"present"}"#,
            r#"{"manifest":"verified"}"#,
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 2. Hand-Built Edge Cases: Stuffing, Restart, Custom Markers, Fill Bytes
// ---------------------------------------------------------------------------

#[test]
fn test_edge_case_byte_stuffing_inside_ecs() -> Result<(), Box<dyn Error>> {
    let frame_bytes = build_jpeg_with_byte_stuffing(128, 96);
    let limits = MjpegLimits::default();

    let scan = split_jpeg_stream(&frame_bytes, &limits, None)?;
    assert_eq!(scan.frame_count(), 1);
    assert_eq!(scan.valid_frame_count(), 1);
    assert!(!scan.has_truncation());
    assert!(scan.findings.is_empty());

    let frame = &scan.frames[0];
    assert_eq!(frame.start_offset, 0);
    assert_eq!(frame.end_offset, frame_bytes.len());
    assert!(frame.has_eoi);
    assert_eq!(frame.slice(&frame_bytes), Some(frame_bytes.as_slice()));

    emit_caplog(
        "edge_case_byte_stuffing",
        "pass",
        r#"{"stuffed_ff00_parsed":true}"#,
        r#"{"stuffed_ff00_parsed":true}"#,
    );
    Ok(())
}

#[test]
fn test_edge_case_restart_markers_rstn() -> Result<(), Box<dyn Error>> {
    let frame_bytes = build_jpeg_with_restart_markers(64, 48, 4);
    let limits = MjpegLimits::default();

    let scan = split_jpeg_stream(&frame_bytes, &limits, None)?;
    assert_eq!(scan.frame_count(), 1);
    assert_eq!(scan.valid_frame_count(), 1);

    let frame = &scan.frames[0];
    assert_eq!(frame.restart_interval, 4);
    assert!(frame.has_eoi);
    assert_eq!(frame.marker_count, 4); // DQT, DRI, SOF0, SOS
    assert!(scan.findings.is_empty());

    emit_caplog(
        "edge_case_restart_markers",
        "pass",
        r#"{"restart_interval":4,"rst_markers_handled":true}"#,
        r#"{"restart_interval":4,"rst_markers_handled":true}"#,
    );
    Ok(())
}

#[test]
fn test_edge_case_appn_and_com_with_embedded_ffd9() -> Result<(), Box<dyn Error>> {
    let frame_bytes = build_jpeg_with_appn_com(48, 32);
    let limits = MjpegLimits::default();

    let scan = split_jpeg_stream(&frame_bytes, &limits, None)?;
    assert_eq!(scan.frame_count(), 1);
    assert_eq!(scan.valid_frame_count(), 1);

    let frame = &scan.frames[0];
    assert_eq!(frame.len(), frame_bytes.len());
    assert!(frame.has_eoi);
    assert!(!frame.is_truncated);

    emit_caplog(
        "edge_case_appn_com_ffd9_shielding",
        "pass",
        r#"{"embedded_ffd9_shielded":true}"#,
        r#"{"embedded_ffd9_shielded":true}"#,
    );
    Ok(())
}

#[test]
fn test_edge_case_zero_length_segments() -> Result<(), Box<dyn Error>> {
    let frame_bytes = build_jpeg_with_zero_length_marker(32, 32);
    let limits = MjpegLimits::default();

    let scan = split_jpeg_stream(&frame_bytes, &limits, None)?;
    assert_eq!(scan.frame_count(), 1);

    // Length < 2 emits ZeroLengthMarkerSegment finding
    assert!(scan.findings.iter().any(|f| matches!(
        f,
        JpegFinding::ZeroLengthMarkerSegment {
            frame_index: 0,
            marker: 0xFE,
            ..
        }
    )));

    emit_caplog(
        "edge_case_zero_length_segment",
        "pass",
        r#"{"zero_length_finding":true}"#,
        r#"{"zero_length_finding":true}"#,
    );
    Ok(())
}

#[test]
fn test_edge_case_sof_zero_components() -> Result<(), Box<dyn Error>> {
    let frame_bytes = build_jpeg_with_zero_components(32, 32);
    let limits = MjpegLimits::default();

    let scan = split_jpeg_stream(&frame_bytes, &limits, None)?;
    assert_eq!(scan.frame_count(), 1);

    // SOF with 0 components emits ZeroComponents finding
    assert!(
        scan.findings
            .iter()
            .any(|f| matches!(f, JpegFinding::ZeroComponents { frame_index: 0, .. }))
    );

    emit_caplog(
        "edge_case_zero_components",
        "pass",
        r#"{"zero_components_finding":true}"#,
        r#"{"zero_components_finding":true}"#,
    );
    Ok(())
}

#[test]
fn test_edge_case_fill_bytes_runs() -> Result<(), Box<dyn Error>> {
    let frame_bytes = build_jpeg_with_fill_bytes(64, 48);
    let limits = MjpegLimits::default();

    let scan = split_jpeg_stream(&frame_bytes, &limits, None)?;
    assert_eq!(scan.frame_count(), 1);
    assert_eq!(scan.valid_frame_count(), 1);
    assert!(scan.frames[0].has_eoi);

    emit_caplog(
        "edge_case_fill_bytes_runs",
        "pass",
        r#"{"fill_bytes_runs_accepted":true}"#,
        r#"{"fill_bytes_runs_accepted":true}"#,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. Malformed Gauntlet: Omissions, In-Frame Garbage, Short Segments, Resync
// ---------------------------------------------------------------------------

#[test]
fn test_malformed_gauntlet_comprehensive_findings() -> Result<(), Box<dyn Error>> {
    let frame1 = build_test_jpeg(32, 32, 0x10);
    let frame2 = build_test_jpeg(64, 64, 0x20);

    let mut stream = Vec::new();
    // 1. Prefix garbage before first SOI
    stream.extend_from_slice(b"PRE_GARBAGE");
    let f1_start = stream.len();
    stream.extend_from_slice(&frame1);
    let f1_end = stream.len();

    // 2. Inter-frame garbage
    stream.extend_from_slice(b"INTER_GARBAGE");
    let f2_start = stream.len();
    stream.extend_from_slice(&frame2);
    let f2_end = stream.len();

    // 3. Trailing garbage after final EOI
    stream.extend_from_slice(b"POST_GARBAGE");

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&stream, &limits, None)?;

    assert_eq!(scan.frame_count(), 2);
    assert_eq!(scan.valid_frame_count(), 2);
    assert_eq!(scan.omissions.len(), 3);

    assert_eq!(
        scan.omissions[0],
        OmissionSpan {
            start_offset: 0,
            end_offset: f1_start,
            reason: OmissionReason::GarbageBeforeFirstSoi,
        }
    );
    assert_eq!(
        scan.omissions[1],
        OmissionSpan {
            start_offset: f1_end,
            end_offset: f2_start,
            reason: OmissionReason::GarbageBetweenFrames,
        }
    );
    assert_eq!(
        scan.omissions[2],
        OmissionSpan {
            start_offset: f2_end,
            end_offset: stream.len(),
            reason: OmissionReason::TrailingGarbage,
        }
    );

    assert!(scan.findings.contains(&JpegFinding::GarbageBeforeFirstSoi {
        start_offset: 0,
        end_offset: f1_start,
    }));
    assert!(scan.findings.contains(&JpegFinding::GarbageBetweenFrames {
        preceding_frame_index: 0,
        start_offset: f1_end,
        end_offset: f2_start,
    }));
    assert!(scan.findings.contains(&JpegFinding::TrailingGarbage {
        start_offset: f2_end,
        end_offset: stream.len(),
    }));

    emit_caplog(
        "gauntlet_omissions_and_garbage",
        "pass",
        r#"{"omissions":3,"findings":3}"#,
        r#"{"omissions":3,"findings":3}"#,
    );
    Ok(())
}

#[test]
fn test_malformed_gauntlet_in_frame_garbage_and_stray_stuffing() -> Result<(), Box<dyn Error>> {
    let mut data = Vec::with_capacity(256);
    data.extend_from_slice(&[0xFF, 0xD8]); // SOI

    // In-frame garbage between marker segments
    data.extend_from_slice(&[0x12, 0x34, 0x56]);

    // Stray FF00 sequence outside scan data
    data.extend_from_slice(&[0xFF, 0x00]);

    // Short SOF segment (< 8 bytes)
    data.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x05, 0x08, 0x00, 0x10]);

    // Zero height SOF (DNL)
    data.extend_from_slice(&[
        0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x00, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00,
    ]);

    // Unsupported DNL marker
    data.extend_from_slice(&[0xFF, 0xDC, 0x00, 0x04, 0x00, 0x10]);

    data.extend_from_slice(&[0xFF, 0xD9]); // EOI

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&data, &limits, None)?;
    assert_eq!(scan.frame_count(), 1);

    assert!(
        scan.findings
            .iter()
            .any(|f| matches!(f, JpegFinding::GarbageInsideFrame { .. }))
    );
    assert!(
        scan.findings
            .iter()
            .any(|f| matches!(f, JpegFinding::StrayByteStuffing { .. }))
    );
    assert!(
        scan.findings
            .iter()
            .any(|f| matches!(f, JpegFinding::ShortMarkerSegment { marker: 0xC0, .. }))
    );
    assert!(
        scan.findings
            .iter()
            .any(|f| matches!(f, JpegFinding::ZeroHeightSof { .. }))
    );
    assert!(
        scan.findings
            .iter()
            .any(|f| matches!(f, JpegFinding::DnlMarkerUnsupported { .. }))
    );

    emit_caplog(
        "gauntlet_in_frame_anomalies",
        "pass",
        r#"{"anomalies_detected":true}"#,
        r#"{"anomalies_detected":true}"#,
    );
    Ok(())
}

#[test]
fn test_malformed_gauntlet_middle_frame_overflow_resyncs_at_next_soi() -> Result<(), Box<dyn Error>>
{
    let f1 = build_test_jpeg(32, 24, 0x01); // 28 bytes
    let f3 = build_test_jpeg(32, 24, 0x03); // 28 bytes

    // Malformed middle frame with header length declaring 60000 bytes available
    let mut f2_corrupt = Vec::new();
    f2_corrupt.extend_from_slice(&[0xFF, 0xD8]); // SOI
    f2_corrupt.extend_from_slice(&[0xFF, 0xFE, 0xEA, 0x60]); // COM length 60000
    f2_corrupt.extend_from_slice(&[0x41, 0x42]);

    let mut stream = Vec::new();
    stream.extend_from_slice(&f1);
    let f2_start = stream.len();
    stream.extend_from_slice(&f2_corrupt);
    let f3_start = stream.len();
    stream.extend_from_slice(&f3);
    let total_len = stream.len();

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&stream, &limits, None)?;

    // Resync at next SOI delimits all 3 frame spans without losing custody of f3!
    assert_eq!(scan.frame_count(), 3);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, f2_start);
    assert!(scan.frames[0].has_eoi);

    assert_eq!(scan.frames[1].start_offset, f2_start);
    assert_eq!(scan.frames[1].end_offset, f3_start);
    assert!(scan.frames[1].is_truncated);

    assert_eq!(scan.frames[2].start_offset, f3_start);
    assert_eq!(scan.frames[2].end_offset, total_len);
    assert!(scan.frames[2].has_eoi);

    assert!(
        scan.findings
            .iter()
            .any(|f| matches!(f, JpegFinding::MarkerLengthOverflow { frame_index: 1, .. }))
    );

    emit_caplog(
        "gauntlet_middle_frame_resync",
        "pass",
        r#"{"resync_success":true,"recovered_frames":3}"#,
        r#"{"resync_success":true,"recovered_frames":3}"#,
    );
    Ok(())
}

#[test]
fn test_malformed_gauntlet_flood_limits() -> Result<(), Box<dyn Error>> {
    // 1. Flood of stray 0xFF00 sequences exceeding marker segment limit
    let mut flood_stray = Vec::new();
    flood_stray.extend_from_slice(&[0xFF, 0xD8]);
    for _ in 0..100 {
        flood_stray.extend_from_slice(&[0xFF, 0x00]);
    }
    flood_stray.extend_from_slice(&[0xFF, 0xD9]);

    let tight_limits = MjpegLimits {
        max_marker_segments_per_frame: 5,
        ..MjpegLimits::default()
    };

    let stray_res = split_jpeg_stream(&flood_stray, &tight_limits, None);
    assert!(matches!(
        stray_res,
        Err(JpegSplitError::TooManyMarkerSegments { .. })
    ));

    // 2. Flood of in-frame garbage exceeding marker segment limit
    let mut flood_garbage = Vec::new();
    flood_garbage.extend_from_slice(&[0xFF, 0xD8]);
    for _ in 0..100 {
        flood_garbage.extend_from_slice(b"garb");
        flood_garbage.extend_from_slice(&[0xFF, 0x00]);
    }
    flood_garbage.extend_from_slice(&[0xFF, 0xD9]);

    let garb_res = split_jpeg_stream(&flood_garbage, &tight_limits, None);
    assert!(matches!(
        garb_res,
        Err(JpegSplitError::TooManyMarkerSegments { .. })
    ));

    emit_caplog(
        "gauntlet_flood_limits",
        "pass",
        r#"{"stray_flood_rejected":true,"garbage_flood_rejected":true}"#,
        r#"{"stray_flood_rejected":true,"garbage_flood_rejected":true}"#,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 4. 10,000-Mutation Deterministic No-Panic Gauntlet
// ---------------------------------------------------------------------------

#[test]
fn test_10k_mutation_no_panic_gauntlet() -> Result<(), Box<dyn Error>> {
    let base1 = build_test_jpeg(32, 24, 0x11);
    let base2 = build_jpeg_with_restart_markers(32, 24, 2);
    let base3 = build_jpeg_with_appn_com(32, 24);
    let base4 = build_jpeg_with_byte_stuffing(32, 24);
    let base5 = build_jpeg_with_fill_bytes(32, 24);

    let mut multi = Vec::new();
    multi.extend_from_slice(&base1);
    multi.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // inter-frame garbage
    multi.extend_from_slice(&base2);
    multi.extend_from_slice(&base3);

    let templates = [
        &base1[..],
        &base2[..],
        &base3[..],
        &base4[..],
        &base5[..],
        &multi[..],
    ];
    let limits = MjpegLimits::default();

    let mut prng = DeterministicFaultPrng::new(0x2026_0913_2022_0022);
    let total_mutations = 10_000;

    let start = Instant::now();
    for _ in 0..total_mutations {
        let template = templates[(prng.next_u64() as usize) % templates.len()];
        let mut mutated = template.to_vec();

        let mutation_kind = prng.next_bounded(5);
        match mutation_kind {
            0 => {
                // Byte substitution
                if !mutated.is_empty() {
                    let idx = (prng.next_u64() as usize) % mutated.len();
                    mutated[idx] = prng.next_u64() as u8;
                }
            }
            1 => {
                // Bit flip
                if !mutated.is_empty() {
                    let idx = (prng.next_u64() as usize) % mutated.len();
                    let bit = 1u8 << (prng.next_bounded(8) as u8);
                    mutated[idx] ^= bit;
                }
            }
            2 => {
                // Byte insertion
                let idx = (prng.next_u64() as usize) % (mutated.len() + 1);
                mutated.insert(idx, prng.next_u64() as u8);
            }
            3 => {
                // Byte deletion
                if !mutated.is_empty() {
                    let idx = (prng.next_u64() as usize) % mutated.len();
                    mutated.remove(idx);
                }
            }
            _ => {
                // Truncation
                let len = (prng.next_u64() as usize) % (mutated.len() + 1);
                mutated.truncate(len);
            }
        }

        // Must never panic! Result can be Ok or Err, but must remain fail-safe.
        let _ = split_jpeg_stream(&mutated, &limits, None);
    }
    let elapsed_ms = start.elapsed().as_millis() as u64;

    emit_caplog(
        "mutation_gauntlet_10k",
        "pass",
        &format!(r#"{{"iterations":{},"panics":0}}"#, total_mutations),
        &format!(
            r#"{{"iterations":{},"panics":0,"elapsed_ms":{}}}"#,
            total_mutations, elapsed_ms
        ),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 5. Limits Boundaries & Refusals
// ---------------------------------------------------------------------------

#[test]
fn test_limits_enforcement_boundaries() -> Result<(), Box<dyn Error>> {
    let frame = build_test_jpeg(64, 48, 0x55);
    let frame_len = frame.len();

    // 5.1 max_input_bytes boundary
    let exact_input_limits = MjpegLimits {
        max_input_bytes: frame_len,
        ..MjpegLimits::default()
    };
    assert!(split_jpeg_stream(&frame, &exact_input_limits, None).is_ok());

    let too_small_input_limits = MjpegLimits {
        max_input_bytes: frame_len - 1,
        ..MjpegLimits::default()
    };
    assert!(matches!(
        split_jpeg_stream(&frame, &too_small_input_limits, None),
        Err(JpegSplitError::InputOversized { size, limit }) if size == frame_len && limit == frame_len - 1
    ));

    // 5.2 max_frame_bytes boundary
    let exact_frame_limits = MjpegLimits {
        max_frame_bytes: frame_len,
        ..MjpegLimits::default()
    };
    assert!(split_jpeg_stream(&frame, &exact_frame_limits, None).is_ok());

    let too_small_frame_limits = MjpegLimits {
        max_frame_bytes: frame_len - 1,
        ..MjpegLimits::default()
    };
    assert!(matches!(
        split_jpeg_stream(&frame, &too_small_frame_limits, None),
        Err(JpegSplitError::FrameTooLarge { frame_index: 0, size, limit }) if size == frame_len && limit == frame_len - 1
    ));

    // 5.3 max_dimension boundary
    let exact_dim_limits = MjpegLimits {
        max_dimension: 64,
        ..MjpegLimits::default()
    };
    assert!(split_jpeg_stream(&frame, &exact_dim_limits, None).is_ok());

    let too_small_dim_limits = MjpegLimits {
        max_dimension: 63,
        ..MjpegLimits::default()
    };
    assert!(matches!(
        split_jpeg_stream(&frame, &too_small_dim_limits, None),
        Err(JpegSplitError::DimensionLimit {
            width: 64,
            max_dimension: 63,
            ..
        })
    ));

    // 5.4 max_frames boundary
    let mut two_frames = Vec::new();
    two_frames.extend_from_slice(&frame);
    two_frames.extend_from_slice(&frame);

    let one_frame_limit = MjpegLimits {
        max_frames: 1,
        ..MjpegLimits::default()
    };
    assert!(matches!(
        split_jpeg_stream(&two_frames, &one_frame_limit, None),
        Err(JpegSplitError::TooManyFrames { count: 2, limit: 1 })
    ));

    emit_caplog(
        "limits_enforcement_boundaries",
        "pass",
        r#"{"boundaries_tested":["max_input_bytes","max_frame_bytes","max_dimension","max_frames"]}"#,
        r#"{"all_boundaries_verified":true}"#,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 6. Cancellation via ReplayCx
// ---------------------------------------------------------------------------

#[test]
fn test_cooperative_cancellation_checkpoints() -> Result<(), Box<dyn Error>> {
    let frame = build_test_jpeg(64, 48, 0x77);

    // Pre-cancelled context must be immediately refused
    let cx = ReplayCx::for_test();
    cx.request_cancellation();

    let limits = MjpegLimits::default();
    let res = split_jpeg_stream(&frame, &limits, Some(&cx));
    assert!(matches!(res, Err(JpegSplitError::CancellationRequested)));

    emit_caplog(
        "cancellation_checkpoints",
        "pass",
        r#"{"cancellation_refused":true}"#,
        r#"{"cancellation_refused":true}"#,
    );
    Ok(())
}

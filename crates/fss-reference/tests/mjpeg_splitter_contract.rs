#![forbid(unsafe_code)]
//! Deterministic contract tests for the bounded MJPEG/JPEG frame splitter.
//!
//! Asserts exact-equality behavior on well-formed, multi-frame, corrupted, truncated,
//! oversize, byte-stuffed, restart-marked, and cancellation-governed streams.

use std::error::Error;

use fss_reference::ReplayCx;
use fss_reference::ingest::{
    JpegFinding, JpegProcess, JpegSplitError, MjpegLimits, OmissionReason, OmissionSpan,
    split_jpeg_stream,
};

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

#[test]
fn single_clean_jpeg_splits_with_exact_spans_and_no_omissions() -> Result<(), Box<dyn Error>> {
    let frame_bytes = build_test_jpeg(640, 480, 0xAA);
    let limits = MjpegLimits::default();

    let scan = split_jpeg_stream(&frame_bytes, &limits, None)?;

    assert_eq!(scan.total_bytes_scanned, frame_bytes.len());
    assert_eq!(scan.frame_count(), 1);
    assert_eq!(scan.valid_frame_count(), 1);
    assert!(!scan.has_truncation());
    assert!(!scan.has_omissions());
    assert!(scan.omissions.is_empty());
    assert!(scan.findings.is_empty());

    let frame = &scan.frames[0];
    assert_eq!(frame.frame_index, 0);
    assert_eq!(frame.start_offset, 0);
    assert_eq!(frame.end_offset, frame_bytes.len());
    assert_eq!(frame.len(), frame_bytes.len());
    assert!(frame.has_eoi);
    assert!(!frame.is_truncated);
    assert_eq!(frame.restart_interval, 0);

    let Some(sof) = &frame.sof else {
        return Err("SOF0 must be present".into());
    };
    assert_eq!(sof.process, JpegProcess::Baseline);
    assert_eq!(sof.marker, 0xC0);
    assert_eq!(sof.precision, 8);
    assert_eq!(sof.width, 640);
    assert_eq!(sof.height, 480);
    assert_eq!(sof.components, 3);

    // Exact slice custody assertion
    assert_eq!(frame.slice(&frame_bytes), Some(frame_bytes.as_slice()));
    Ok(())
}

#[test]
fn multi_frame_mjpeg_concatenation_produces_exact_contiguous_spans() -> Result<(), Box<dyn Error>> {
    let frame1 = build_test_jpeg(320, 240, 0x01);
    let frame2 = build_test_jpeg(640, 480, 0x02);
    let frame3 = build_test_jpeg(1280, 720, 0x03);

    let mut stream = Vec::new();
    stream.extend_from_slice(&frame1);
    stream.extend_from_slice(&frame2);
    stream.extend_from_slice(&frame3);

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&stream, &limits, None)?;

    assert_eq!(scan.total_bytes_scanned, stream.len());
    assert_eq!(scan.frame_count(), 3);
    assert_eq!(scan.valid_frame_count(), 3);
    assert!(scan.omissions.is_empty());
    assert!(scan.findings.is_empty());

    // Frame 0
    assert_eq!(scan.frames[0].frame_index, 0);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, frame1.len());
    assert_eq!(scan.frames[0].slice(&stream), Some(frame1.as_slice()));
    assert_eq!(scan.frames[0].sof.as_ref().map(|s| s.width), Some(320));
    assert_eq!(scan.frames[0].sof.as_ref().map(|s| s.height), Some(240));

    // Frame 1
    assert_eq!(scan.frames[1].frame_index, 1);
    assert_eq!(scan.frames[1].start_offset, frame1.len());
    assert_eq!(scan.frames[1].end_offset, frame1.len() + frame2.len());
    assert_eq!(scan.frames[1].slice(&stream), Some(frame2.as_slice()));
    assert_eq!(scan.frames[1].sof.as_ref().map(|s| s.width), Some(640));
    assert_eq!(scan.frames[1].sof.as_ref().map(|s| s.height), Some(480));

    // Frame 2
    assert_eq!(scan.frames[2].frame_index, 2);
    assert_eq!(scan.frames[2].start_offset, frame1.len() + frame2.len());
    assert_eq!(scan.frames[2].end_offset, stream.len());
    assert_eq!(scan.frames[2].slice(&stream), Some(frame3.as_slice()));
    assert_eq!(scan.frames[2].sof.as_ref().map(|s| s.width), Some(1280));
    assert_eq!(scan.frames[2].sof.as_ref().map(|s| s.height), Some(720));
    Ok(())
}

#[test]
fn garbage_before_first_soi_recorded_as_omission_span_and_finding() -> Result<(), Box<dyn Error>> {
    let prefix_garbage = b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace\r\n\r\n";
    let frame = build_test_jpeg(640, 480, 0x55);

    let mut stream = Vec::new();
    stream.extend_from_slice(prefix_garbage);
    stream.extend_from_slice(&frame);

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&stream, &limits, None)?;

    assert_eq!(scan.frame_count(), 1);
    assert_eq!(scan.omissions.len(), 1);
    assert_eq!(
        scan.omissions[0],
        OmissionSpan {
            start_offset: 0,
            end_offset: prefix_garbage.len(),
            reason: OmissionReason::GarbageBeforeFirstSoi,
        }
    );
    assert_eq!(
        scan.omissions[0].slice(&stream),
        Some(prefix_garbage.as_slice())
    );

    assert_eq!(
        scan.findings,
        vec![JpegFinding::GarbageBeforeFirstSoi {
            start_offset: 0,
            end_offset: prefix_garbage.len(),
        }]
    );

    assert_eq!(scan.frames[0].start_offset, prefix_garbage.len());
    assert_eq!(scan.frames[0].end_offset, stream.len());
    Ok(())
}

#[test]
fn garbage_between_frames_recorded_as_omission_span_and_finding() -> Result<(), Box<dyn Error>> {
    let frame1 = build_test_jpeg(640, 480, 0x11);
    let separator = b"--boundary\r\nContent-Type: image/jpeg\r\n\r\n";
    let frame2 = build_test_jpeg(640, 480, 0x22);

    let mut stream = Vec::new();
    stream.extend_from_slice(&frame1);
    stream.extend_from_slice(separator);
    stream.extend_from_slice(&frame2);

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&stream, &limits, None)?;

    assert_eq!(scan.frame_count(), 2);
    assert_eq!(scan.omissions.len(), 1);

    let sep_start = frame1.len();
    let sep_end = frame1.len() + separator.len();

    assert_eq!(
        scan.omissions[0],
        OmissionSpan {
            start_offset: sep_start,
            end_offset: sep_end,
            reason: OmissionReason::GarbageBetweenFrames,
        }
    );
    assert_eq!(scan.omissions[0].slice(&stream), Some(separator.as_slice()));

    assert_eq!(
        scan.findings,
        vec![JpegFinding::GarbageBetweenFrames {
            preceding_frame_index: 0,
            start_offset: sep_start,
            end_offset: sep_end,
        }]
    );

    assert_eq!(scan.frames[1].start_offset, sep_end);
    Ok(())
}

#[test]
fn trailing_garbage_after_last_eoi_recorded_as_omission_span_and_finding()
-> Result<(), Box<dyn Error>> {
    let frame = build_test_jpeg(640, 480, 0x99);
    let trailing = b"\r\n--boundary--\r\n";

    let mut stream = Vec::new();
    stream.extend_from_slice(&frame);
    stream.extend_from_slice(trailing);

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&stream, &limits, None)?;

    assert_eq!(scan.frame_count(), 1);
    assert_eq!(scan.omissions.len(), 1);

    assert_eq!(
        scan.omissions[0],
        OmissionSpan {
            start_offset: frame.len(),
            end_offset: stream.len(),
            reason: OmissionReason::TrailingGarbage,
        }
    );
    assert_eq!(scan.omissions[0].slice(&stream), Some(trailing.as_slice()));

    assert_eq!(
        scan.findings,
        vec![JpegFinding::TrailingGarbage {
            start_offset: frame.len(),
            end_offset: stream.len(),
        }]
    );
    Ok(())
}

#[test]
fn truncated_final_frame_without_eoi_flags_is_truncated_and_emits_finding()
-> Result<(), Box<dyn Error>> {
    let mut frame = build_test_jpeg(640, 480, 0x77);
    // Remove trailing 0xFF, 0xD9 (EOI)
    let truncated_len = frame.len() - 2;
    frame.truncate(truncated_len);

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&frame, &limits, None)?;

    assert_eq!(scan.frame_count(), 1);
    assert_eq!(scan.valid_frame_count(), 0);
    assert!(scan.has_truncation());

    let frame_span = &scan.frames[0];
    assert!(!frame_span.has_eoi);
    assert!(frame_span.is_truncated);
    assert_eq!(frame_span.start_offset, 0);
    assert_eq!(frame_span.end_offset, truncated_len);

    // Source custody retained completely
    assert_eq!(frame_span.slice(&frame), Some(frame.as_slice()));

    assert_eq!(
        scan.findings,
        vec![JpegFinding::TruncatedFrame {
            frame_index: 0,
            start_offset: 0,
            end_offset: truncated_len,
        }]
    );
    Ok(())
}

#[test]
fn mid_stream_truncation_when_new_soi_appears_without_eoi() -> Result<(), Box<dyn Error>> {
    let mut frame1 = build_test_jpeg(320, 240, 0x11);
    frame1.truncate(frame1.len() - 2); // Frame 1 truncated (no EOI)
    let frame2 = build_test_jpeg(640, 480, 0x22); // Frame 2 starts immediately

    let mut stream = Vec::new();
    stream.extend_from_slice(&frame1);
    stream.extend_from_slice(&frame2);

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&stream, &limits, None)?;

    assert_eq!(scan.frame_count(), 2);
    assert_eq!(scan.valid_frame_count(), 1);

    assert!(scan.frames[0].is_truncated);
    assert!(!scan.frames[0].has_eoi);
    assert_eq!(scan.frames[0].end_offset, frame1.len());

    assert!(!scan.frames[1].is_truncated);
    assert!(scan.frames[1].has_eoi);
    assert_eq!(scan.frames[1].start_offset, frame1.len());

    assert_eq!(
        scan.findings,
        vec![JpegFinding::TruncatedFrame {
            frame_index: 0,
            start_offset: 0,
            end_offset: frame1.len(),
        }]
    );
    Ok(())
}

#[test]
fn byte_stuffing_ff00_in_ecs_does_not_prematurely_terminate_frame() -> Result<(), Box<dyn Error>> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xFF, 0xD8]); // SOI

    // SOF0
    frame.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
    frame.extend_from_slice(&100u16.to_be_bytes());
    frame.extend_from_slice(&100u16.to_be_bytes());
    frame.push(3);
    frame.extend_from_slice(&[1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0]);

    // SOS
    frame.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x0C, 0x03]);
    frame.extend_from_slice(&[1, 0x00, 2, 0x11, 3, 0x11, 0x00, 0x3F, 0x00]);

    // ECS with multiple stuffed FF00 sequences
    frame.extend_from_slice(&[0x12, 0xFF, 0x00, 0x34, 0xFF, 0x00, 0xFF, 0x00, 0x56]);

    // EOI
    frame.extend_from_slice(&[0xFF, 0xD9]);

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&frame, &limits, None)?;

    assert_eq!(scan.frame_count(), 1);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 46);
    assert_eq!(scan.frames[0].marker_count, 2);
    assert!(scan.findings.is_empty());
    Ok(())
}

#[test]
fn restart_markers_in_ecs_and_dri_are_handled_correctly() -> Result<(), Box<dyn Error>> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xFF, 0xD8]); // SOI

    // DRI: length = 4, Ri = 64
    frame.extend_from_slice(&[0xFF, 0xDD, 0x00, 0x04]);
    frame.extend_from_slice(&64u16.to_be_bytes());

    // SOF0
    frame.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
    frame.extend_from_slice(&100u16.to_be_bytes());
    frame.extend_from_slice(&100u16.to_be_bytes());
    frame.push(3);
    frame.extend_from_slice(&[1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0]);

    // SOS
    frame.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x0C, 0x03]);
    frame.extend_from_slice(&[1, 0x00, 2, 0x11, 3, 0x11, 0x00, 0x3F, 0x00]);

    // ECS with restart markers: RST0 (0xFFD0), RST1 (0xFFD1)
    frame.extend_from_slice(&[0x10, 0xFF, 0xD0, 0x20, 0xFF, 0xD1, 0x30]);

    // EOI
    frame.extend_from_slice(&[0xFF, 0xD9]);

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&frame, &limits, None)?;

    assert_eq!(scan.frame_count(), 1);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 50);
    assert_eq!(scan.frames[0].marker_count, 3);
    assert_eq!(scan.frames[0].restart_interval, 64);
    assert!(scan.findings.is_empty());
    Ok(())
}

#[test]
fn appn_containing_ffd9_bytes_is_shielded_by_declared_length() -> Result<(), Box<dyn Error>> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xFF, 0xD8]); // SOI

    // APP1 segment containing 0xFF, 0xD9 inside its payload!
    // Length = 8 (2 length + 6 payload)
    frame.extend_from_slice(&[0xFF, 0xE1, 0x00, 0x08]);
    frame.extend_from_slice(&[0xAA, 0xFF, 0xD9, 0xBB, 0xCC, 0xDD]);

    // SOF0
    frame.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
    frame.extend_from_slice(&100u16.to_be_bytes());
    frame.extend_from_slice(&100u16.to_be_bytes());
    frame.push(3);
    frame.extend_from_slice(&[1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0]);

    // SOS
    frame.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x0C, 0x03]);
    frame.extend_from_slice(&[1, 0x00, 2, 0x11, 3, 0x11, 0x00, 0x3F, 0x00]);

    // ECS
    frame.extend_from_slice(&[0x42, 0x43]);

    // Real terminating EOI
    frame.extend_from_slice(&[0xFF, 0xD9]);

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&frame, &limits, None)?;

    assert_eq!(scan.frame_count(), 1);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);
    assert_eq!(scan.frames[0].end_offset, frame.len());
    Ok(())
}

#[test]
fn stream_with_no_soi_returns_typed_no_soi_error() -> Result<(), Box<dyn Error>> {
    let garbage = b"THIS_IS_NOT_A_JPEG_STREAM_AT_ALL";
    let limits = MjpegLimits::default();

    match split_jpeg_stream(garbage, &limits, None) {
        Err(JpegSplitError::NoSoi) => Ok(()),
        other => Err(format!("expected NoSoi, got {other:?}").into()),
    }
}

#[test]
fn empty_stream_returns_typed_no_soi_error() -> Result<(), Box<dyn Error>> {
    let empty = b"";
    let limits = MjpegLimits::default();

    match split_jpeg_stream(empty, &limits, None) {
        Err(JpegSplitError::NoSoi) => Ok(()),
        other => Err(format!("expected NoSoi, got {other:?}").into()),
    }
}

#[test]
fn marker_length_overflow_fails_closed_before_allocation() -> Result<(), Box<dyn Error>> {
    let mut stream = Vec::new();
    stream.extend_from_slice(&[0xFF, 0xD8]); // SOI
    // APP0 with declared length 1000, but stream ends immediately
    stream.extend_from_slice(&[0xFF, 0xE0, 0x03, 0xE8]); // length 1000

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&stream, &limits, None)?;
    assert_eq!(scan.frames.len(), 1);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 6);
    assert!(!scan.frames[0].has_eoi);
    assert!(scan.frames[0].is_truncated);
    assert_eq!(
        scan.findings,
        vec![
            JpegFinding::MarkerLengthOverflow {
                frame_index: 0,
                offset: 2,
                marker: 0xE0,
                length: 1000,
                available: 2,
            },
            JpegFinding::TruncatedFrame {
                frame_index: 0,
                start_offset: 0,
                end_offset: 6,
            },
        ]
    );
    Ok(())
}

#[test]
fn dimension_limit_exceeded_rejects_at_sof_before_allocation() -> Result<(), Box<dyn Error>> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xFF, 0xD8]); // SOI

    // SOF0 with width = 16385 (> max_dimension 16384)
    frame.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
    frame.extend_from_slice(&480u16.to_be_bytes()); // height
    frame.extend_from_slice(&16385u16.to_be_bytes()); // width 16385!
    frame.push(3);
    frame.extend_from_slice(&[1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0]);

    // SOS + ECS + EOI
    frame.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x0C, 0x03]);
    frame.extend_from_slice(&[1, 0x00, 2, 0x11, 3, 0x11, 0x00, 0x3F, 0x00]);
    frame.extend_from_slice(&[0x11, 0x22, 0xFF, 0xD9]);

    let limits = MjpegLimits::default();
    match split_jpeg_stream(&frame, &limits, None) {
        Err(JpegSplitError::DimensionLimit {
            width,
            height,
            max_dimension,
        }) => {
            assert_eq!(width, 16385);
            assert_eq!(height, 480);
            assert_eq!(max_dimension, 16384);
            Ok(())
        }
        other => Err(format!("expected DimensionLimit, got {other:?}").into()),
    }
}

#[test]
fn height_dimension_limit_exceeded_rejects_at_sof() -> Result<(), Box<dyn Error>> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xFF, 0xD8]); // SOI

    // SOF0 with height = 20000 (> max_dimension 16384)
    frame.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
    frame.extend_from_slice(&20000u16.to_be_bytes()); // height 20000!
    frame.extend_from_slice(&640u16.to_be_bytes()); // width
    frame.push(3);
    frame.extend_from_slice(&[1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0]);

    // SOS + ECS + EOI
    frame.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x0C, 0x03]);
    frame.extend_from_slice(&[1, 0x00, 2, 0x11, 3, 0x11, 0x00, 0x3F, 0x00]);
    frame.extend_from_slice(&[0x11, 0x22, 0xFF, 0xD9]);

    let limits = MjpegLimits::default();
    match split_jpeg_stream(&frame, &limits, None) {
        Err(JpegSplitError::DimensionLimit {
            width,
            height,
            max_dimension,
        }) => {
            assert_eq!(width, 640);
            assert_eq!(height, 20000);
            assert_eq!(max_dimension, 16384);
            Ok(())
        }
        other => Err(format!("expected DimensionLimit, got {other:?}").into()),
    }
}

#[test]
fn input_oversized_limit_enforced_before_scanning() -> Result<(), Box<dyn Error>> {
    let frame = build_test_jpeg(320, 240, 0x01);
    let limit = frame.len() - 1;
    let limits = MjpegLimits {
        max_input_bytes: limit,
        ..Default::default()
    };

    match split_jpeg_stream(&frame, &limits, None) {
        Err(JpegSplitError::InputOversized {
            size,
            limit: err_limit,
        }) => {
            assert_eq!(size, frame.len());
            assert_eq!(err_limit, limit);
            Ok(())
        }
        other => Err(format!("expected InputOversized, got {other:?}").into()),
    }
}

#[test]
fn frame_too_large_limit_enforced() -> Result<(), Box<dyn Error>> {
    let frame = build_test_jpeg(320, 240, 0x01);
    let limit = frame.len() - 1;
    let limits = MjpegLimits {
        max_frame_bytes: limit,
        ..Default::default()
    };

    match split_jpeg_stream(&frame, &limits, None) {
        Err(JpegSplitError::FrameTooLarge {
            frame_index,
            size,
            limit: err_limit,
        }) => {
            assert_eq!(frame_index, 0);
            assert_eq!(size, frame.len());
            assert_eq!(err_limit, limit);
            Ok(())
        }
        other => Err(format!("expected FrameTooLarge, got {other:?}").into()),
    }
}

#[test]
fn max_frames_limit_enforced() -> Result<(), Box<dyn Error>> {
    let frame1 = build_test_jpeg(320, 240, 0x01);
    let frame2 = build_test_jpeg(320, 240, 0x02);

    let mut stream = Vec::new();
    stream.extend_from_slice(&frame1);
    stream.extend_from_slice(&frame2);

    let limits = MjpegLimits {
        max_frames: 1,
        ..Default::default()
    };

    match split_jpeg_stream(&stream, &limits, None) {
        Err(JpegSplitError::TooManyFrames { count, limit }) => {
            assert_eq!(count, 2);
            assert_eq!(limit, 1);
            Ok(())
        }
        other => Err(format!("expected TooManyFrames, got {other:?}").into()),
    }
}

#[test]
fn max_marker_segments_limit_enforced() -> Result<(), Box<dyn Error>> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xFF, 0xD8]); // SOI

    // Inject 5 COM (comment) segments
    for _ in 0..5 {
        frame.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x04, 0xAA, 0xBB]);
    }
    frame.extend_from_slice(&[0xFF, 0xD9]); // EOI

    let limits = MjpegLimits {
        max_marker_segments_per_frame: 3,
        ..Default::default()
    };

    match split_jpeg_stream(&frame, &limits, None) {
        Err(JpegSplitError::TooManyMarkerSegments {
            frame_index,
            count,
            limit,
        }) => {
            assert_eq!(frame_index, 0);
            assert_eq!(count, 4);
            assert_eq!(limit, 3);
            Ok(())
        }
        other => Err(format!("expected TooManyMarkerSegments, got {other:?}").into()),
    }
}

#[test]
fn cooperative_cancellation_aborts_scanning_cleanly() -> Result<(), Box<dyn Error>> {
    let frame = build_test_jpeg(640, 480, 0x01);
    let limits = MjpegLimits::default();

    let cx = ReplayCx::for_test();
    cx.request_cancellation();

    match split_jpeg_stream(&frame, &limits, Some(&cx)) {
        Err(JpegSplitError::CancellationRequested) => Ok(()),
        other => Err(format!("expected CancellationRequested, got {other:?}").into()),
    }
}

#[test]
fn zero_length_marker_segment_records_finding() -> Result<(), Box<dyn Error>> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xFF, 0xD8]); // SOI

    // Segment with declared length 0 (< 2)
    frame.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x00]);

    // SOF0
    frame.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
    frame.extend_from_slice(&100u16.to_be_bytes());
    frame.extend_from_slice(&100u16.to_be_bytes());
    frame.push(3);
    frame.extend_from_slice(&[1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0]);

    // SOS + ECS + EOI
    frame.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x0C, 0x03]);
    frame.extend_from_slice(&[1, 0x00, 2, 0x11, 3, 0x11, 0x00, 0x3F, 0x00]);
    frame.extend_from_slice(&[0x11, 0x22, 0xFF, 0xD9]);

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&frame, &limits, None)?;

    assert_eq!(scan.frame_count(), 1);
    assert_eq!(
        scan.findings,
        vec![JpegFinding::ZeroLengthMarkerSegment {
            frame_index: 0,
            marker: 0xFE,
            offset: 2,
        }]
    );
    Ok(())
}

#[test]
fn zero_components_in_sof_records_finding() -> Result<(), Box<dyn Error>> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xFF, 0xD8]); // SOI

    // SOF0 with 0 components
    frame.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x08, 0x08]);
    frame.extend_from_slice(&100u16.to_be_bytes());
    frame.extend_from_slice(&100u16.to_be_bytes());
    frame.push(0); // 0 components!

    // SOS + ECS + EOI
    frame.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x06, 0x00, 0x00, 0x3F, 0x00]);
    frame.extend_from_slice(&[0x11, 0x22, 0xFF, 0xD9]);

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&frame, &limits, None)?;

    assert_eq!(scan.frame_count(), 1);
    assert_eq!(scan.frames[0].sof.as_ref().map(|s| s.components), Some(0));
    assert_eq!(
        scan.findings,
        vec![JpegFinding::ZeroComponents {
            frame_index: 0,
            offset: 2,
        }]
    );
    Ok(())
}

#[test]
fn progressive_and_12bit_processes_are_recorded_without_split_error() -> Result<(), Box<dyn Error>>
{
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xFF, 0xD8]); // SOI

    // SOF2 (Progressive), 12-bit precision
    frame.extend_from_slice(&[0xFF, 0xC2, 0x00, 0x11, 0x0C]);
    frame.extend_from_slice(&720u16.to_be_bytes());
    frame.extend_from_slice(&1280u16.to_be_bytes());
    frame.push(3);
    frame.extend_from_slice(&[1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0]);

    // SOS + ECS + EOI
    frame.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x0C, 0x03]);
    frame.extend_from_slice(&[1, 0x00, 2, 0x11, 3, 0x11, 0x00, 0x3F, 0x00]);
    frame.extend_from_slice(&[0x11, 0x22, 0xFF, 0xD9]);

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&frame, &limits, None)?;

    assert_eq!(scan.frame_count(), 1);
    let Some(sof) = &scan.frames[0].sof else {
        return Err("SOF must be recorded".into());
    };
    assert_eq!(sof.process, JpegProcess::Progressive);
    assert_eq!(sof.precision, 12);
    assert_eq!(sof.width, 1280);
    assert_eq!(sof.height, 720);
    Ok(())
}

#[test]
fn com_containing_ffd9_bytes_is_shielded_by_declared_length() -> Result<(), Box<dyn Error>> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0xFF, 0xD8]); // SOI

    // COM segment containing 0xFF, 0xD9 inside its payload
    // Length = 8 (2 length + 6 payload bytes)
    frame.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x08]);
    frame.extend_from_slice(&[0x11, 0xFF, 0xD9, 0x22, 0x33, 0x44]);

    // SOF0
    frame.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
    frame.extend_from_slice(&100u16.to_be_bytes());
    frame.extend_from_slice(&100u16.to_be_bytes());
    frame.push(3);
    frame.extend_from_slice(&[1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0]);

    // SOS
    frame.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x0C, 0x03]);
    frame.extend_from_slice(&[1, 0x00, 2, 0x11, 3, 0x11, 0x00, 0x3F, 0x00]);

    // ECS
    frame.extend_from_slice(&[0x55, 0x66]);

    // Real terminating EOI
    frame.extend_from_slice(&[0xFF, 0xD9]);

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&frame, &limits, None)?;

    assert_eq!(scan.frame_count(), 1);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);
    assert_eq!(scan.frames[0].end_offset, frame.len());
    Ok(())
}

#[test]
fn mid_stream_dimension_change_splits_both_frames_with_independent_sof_info()
-> Result<(), Box<dyn Error>> {
    let frame1 = build_test_jpeg(640, 480, 0x10);
    let frame2 = build_test_jpeg(1920, 1080, 0x20);

    let mut stream = Vec::new();
    stream.extend_from_slice(&frame1);
    stream.extend_from_slice(&frame2);

    let limits = MjpegLimits::default();
    let scan = split_jpeg_stream(&stream, &limits, None)?;

    assert_eq!(scan.frame_count(), 2);
    assert_eq!(scan.valid_frame_count(), 2);
    assert!(!scan.has_truncation());

    // Frame 0: 640x480
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, frame1.len());
    let Some(sof0) = &scan.frames[0].sof else {
        return Err("SOF0 must be present".into());
    };
    assert_eq!(sof0.width, 640);
    assert_eq!(sof0.height, 480);

    // Frame 1: 1920x1080
    assert_eq!(scan.frames[1].start_offset, frame1.len());
    assert_eq!(scan.frames[1].end_offset, stream.len());
    let Some(sof1) = &scan.frames[1].sof else {
        return Err("SOF1 must be present".into());
    };
    assert_eq!(sof1.width, 1920);
    assert_eq!(sof1.height, 1080);

    Ok(())
}

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

#[test]
fn probe_ff_fill_runs_before_markers_and_eoi() -> Result<(), Box<dyn Error>> {
    let mut f = vec![0xFF, 0xD8, 0xFF, 0xFF];
    f.extend(helper_sof0(16, 8));
    f.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
    f.extend(helper_sos1());
    f.extend_from_slice(&[0x11, 0x22, 0xFF, 0xFF, 0xFF, 0xD9]);
    let scan = split_jpeg_stream(&f, &MjpegLimits::default(), None)?;
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
    assert!(scan.findings.is_empty());
    Ok(())
}

#[test]
fn probe_rst0_to_rst7_in_ecs_with_fill_before_rst() -> Result<(), Box<dyn Error>> {
    let mut ecs = Vec::new();
    for m in 0xD0u8..=0xD7 {
        ecs.extend_from_slice(&[0x01, 0xFF, m]);
    }
    ecs.extend_from_slice(&[0x09, 0xFF, 0xFF, 0xD3, 0x0A]);
    let f = helper_frame(8, 8, &ecs);
    let scan = split_jpeg_stream(&f, &MjpegLimits::default(), None)?;
    assert_eq!(scan.frames.len(), 1);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 56);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);
    assert_eq!(scan.frames[0].marker_count, 2);
    assert!(scan.findings.is_empty());
    Ok(())
}

#[test]
fn probe_segment_length_overruns_by_one() -> Result<(), Box<dyn Error>> {
    let f = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x05, 0xAA, 0xBB];
    let scan = split_jpeg_stream(&f, &MjpegLimits::default(), None)?;
    assert_eq!(scan.frames.len(), 1);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 8);
    assert!(!scan.frames[0].has_eoi);
    assert!(scan.frames[0].is_truncated);
    assert_eq!(
        scan.findings,
        vec![
            JpegFinding::MarkerLengthOverflow {
                frame_index: 0,
                offset: 2,
                marker: 0xE0,
                length: 5,
                available: 4,
            },
            JpegFinding::TruncatedFrame {
                frame_index: 0,
                start_offset: 0,
                end_offset: 8,
            },
        ]
    );
    Ok(())
}

#[test]
fn probe_segment_ends_exactly_at_eof_without_eoi_is_truncated() -> Result<(), Box<dyn Error>> {
    let f = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0xAA, 0xBB];
    let scan = split_jpeg_stream(&f, &MjpegLimits::default(), None)?;
    assert_eq!(scan.frames.len(), 1);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 8);
    assert!(!scan.frames[0].has_eoi);
    assert!(scan.frames[0].is_truncated);
    assert_eq!(
        scan.findings,
        vec![JpegFinding::TruncatedFrame {
            frame_index: 0,
            start_offset: 0,
            end_offset: 8,
        }]
    );
    Ok(())
}

#[test]
fn probe_length_field_itself_truncated() -> Result<(), Box<dyn Error>> {
    let f = [0xFF, 0xD8, 0xFF, 0xE0, 0x00];
    let scan = split_jpeg_stream(&f, &MjpegLimits::default(), None)?;
    assert_eq!(scan.frames.len(), 1);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 5);
    assert!(!scan.frames[0].has_eoi);
    assert!(scan.frames[0].is_truncated);
    assert_eq!(
        scan.findings,
        vec![
            JpegFinding::MarkerLengthOverflow {
                frame_index: 0,
                offset: 2,
                marker: 0xE0,
                length: 0,
                available: 1,
            },
            JpegFinding::TruncatedFrame {
                frame_index: 0,
                start_offset: 0,
                end_offset: 5,
            },
        ]
    );
    Ok(())
}

#[test]
fn probe_soi_only_at_eof_is_truncated() -> Result<(), Box<dyn Error>> {
    let f = [0xFF, 0xD8];
    let scan = split_jpeg_stream(&f, &MjpegLimits::default(), None)?;
    assert_eq!(scan.frames.len(), 1);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 2);
    assert!(!scan.frames[0].has_eoi);
    assert!(scan.frames[0].is_truncated);
    assert_eq!(
        scan.findings,
        vec![JpegFinding::TruncatedFrame {
            frame_index: 0,
            start_offset: 0,
            end_offset: 2,
        }]
    );
    Ok(())
}

#[test]
fn probe_trailing_bare_soi_after_good_frame_is_truncated() -> Result<(), Box<dyn Error>> {
    let mut f = helper_frame(8, 8, &[0x11]);
    f.extend_from_slice(&[0xFF, 0xD8]);
    let scan = split_jpeg_stream(&f, &MjpegLimits::default(), None)?;
    assert_eq!(scan.frames.len(), 2);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 28);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);
    assert_eq!(scan.frames[1].start_offset, 28);
    assert_eq!(scan.frames[1].end_offset, 30);
    assert!(!scan.frames[1].has_eoi);
    assert!(scan.frames[1].is_truncated);
    assert_eq!(
        scan.findings,
        vec![JpegFinding::TruncatedFrame {
            frame_index: 1,
            start_offset: 28,
            end_offset: 30,
        }]
    );
    Ok(())
}

#[test]
fn probe_garbage_inside_frame_between_segments_is_not_silent() -> Result<(), Box<dyn Error>> {
    let mut f = vec![0xFF, 0xD8];
    f.extend_from_slice(b"XYZ");
    f.extend(helper_sof0(8, 8));
    f.extend(helper_sos1());
    f.extend_from_slice(&[0x11, 0xFF, 0xD9]);
    let scan = split_jpeg_stream(&f, &MjpegLimits::default(), None)?;
    assert!(!scan.findings.is_empty());
    assert_eq!(
        scan.findings,
        vec![JpegFinding::GarbageInsideFrame {
            frame_index: 0,
            start_offset: 2,
            end_offset: 5,
        }]
    );
    Ok(())
}

#[test]
fn probe_max_frame_and_input_bytes_boundary() -> Result<(), Box<dyn Error>> {
    let f = helper_frame(8, 8, &[0x11, 0x22, 0x33]);
    let n = f.len();
    let at = MjpegLimits {
        max_frame_bytes: n,
        max_input_bytes: n,
        ..Default::default()
    };
    let scan = split_jpeg_stream(&f, &at, None)?;
    assert_eq!(scan.frames.len(), 1);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, n);

    let fb = MjpegLimits {
        max_frame_bytes: n - 1,
        ..Default::default()
    };
    assert_eq!(
        split_jpeg_stream(&f, &fb, None),
        Err(JpegSplitError::FrameTooLarge {
            frame_index: 0,
            size: n,
            limit: n - 1,
        })
    );

    let ib = MjpegLimits {
        max_input_bytes: n - 1,
        ..Default::default()
    };
    assert_eq!(
        split_jpeg_stream(&f, &ib, None),
        Err(JpegSplitError::InputOversized {
            size: n,
            limit: n - 1,
        })
    );
    Ok(())
}

#[test]
fn probe_dimension_boundary() -> Result<(), Box<dyn Error>> {
    let ok = helper_frame(16384, 16384, &[0x11]);
    let scan = split_jpeg_stream(&ok, &MjpegLimits::default(), None)?;
    assert_eq!(scan.frames.len(), 1);

    let bad = helper_frame(16384, 16385, &[0x11]);
    assert_eq!(
        split_jpeg_stream(&bad, &MjpegLimits::default(), None),
        Err(JpegSplitError::DimensionLimit {
            width: 16384,
            height: 16385,
            max_dimension: 16384,
        })
    );
    Ok(())
}

#[test]
fn probe_stray_ff00_outside_ecs_is_not_silent() -> Result<(), Box<dyn Error>> {
    let mut f = vec![0xFF, 0xD8, 0xFF, 0x00];
    f.extend(helper_sof0(8, 8));
    f.extend(helper_sos1());
    f.extend_from_slice(&[0x11, 0xFF, 0xD9]);
    let scan = split_jpeg_stream(&f, &MjpegLimits::default(), None)?;
    assert!(!scan.findings.is_empty());
    assert_eq!(
        scan.findings,
        vec![JpegFinding::StrayByteStuffing {
            frame_index: 0,
            offset: 2,
        }]
    );
    Ok(())
}

#[test]
fn probe_truncation_inside_header_of_last_frame_keeps_prior_custody() -> Result<(), Box<dyn Error>>
{
    let a = helper_frame(8, 8, &[0x11]);
    let mut s = a.clone();
    s.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x43, 0x00, 0x10]);
    let scan = split_jpeg_stream(&s, &MjpegLimits::default(), None)?;
    assert_eq!(scan.frames.len(), 2);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 28);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);

    assert_eq!(scan.frames[1].start_offset, 28);
    assert_eq!(scan.frames[1].end_offset, 36);
    assert!(!scan.frames[1].has_eoi);
    assert!(scan.frames[1].is_truncated);
    assert_eq!(
        scan.findings,
        vec![
            JpegFinding::MarkerLengthOverflow {
                frame_index: 1,
                offset: 30,
                marker: 0xDB,
                length: 67,
                available: 4,
            },
            JpegFinding::TruncatedFrame {
                frame_index: 1,
                start_offset: 28,
                end_offset: 36,
            },
        ]
    );
    Ok(())
}

#[test]
fn probe_dnl_after_first_scan_is_recorded() -> Result<(), Box<dyn Error>> {
    let mut f = vec![0xFF, 0xD8];
    f.extend(helper_sof0(8, 0));
    f.extend(helper_sos1());
    f.extend_from_slice(&[0x11, 0xFF, 0xDC, 0x00, 0x04, 0x00, 0x08, 0xFF, 0xD9]);
    let scan = split_jpeg_stream(&f, &MjpegLimits::default(), None)?;
    assert_eq!(
        scan.findings,
        vec![
            JpegFinding::ZeroHeightSof {
                frame_index: 0,
                offset: 2,
            },
            JpegFinding::DnlMarkerUnsupported {
                frame_index: 0,
                offset: 26,
            },
        ]
    );
    Ok(())
}

#[test]
fn probe_second_sof_with_oversize_dimensions() -> Result<(), Box<dyn Error>> {
    let mut f = vec![0xFF, 0xD8];
    f.extend(helper_sof0(8, 8));
    f.extend(helper_sof0(65535, 65535));
    f.extend(helper_sos1());
    f.extend_from_slice(&[0x11, 0xFF, 0xD9]);
    let r = split_jpeg_stream(&f, &MjpegLimits::default(), None);
    assert_eq!(
        r,
        Err(JpegSplitError::DimensionLimit {
            width: 65535,
            height: 65535,
            max_dimension: 16384,
        })
    );
    Ok(())
}

#[test]
fn probe_standalone_marker_flood_vs_segment_limit() -> Result<(), Box<dyn Error>> {
    let mut f = vec![0xFF, 0xD8];
    for _ in 0..100 {
        f.extend_from_slice(&[0xFF, 0x01]);
    }
    f.extend_from_slice(&[0xFF, 0xD9]);
    let lim = MjpegLimits {
        max_marker_segments_per_frame: 3,
        ..Default::default()
    };
    let r = split_jpeg_stream(&f, &lim, None);
    assert_eq!(
        r,
        Err(JpegSplitError::TooManyMarkerSegments {
            frame_index: 0,
            count: 4,
            limit: 3,
        })
    );
    Ok(())
}

#[test]
fn probe_sof_with_short_length_is_not_silent() -> Result<(), Box<dyn Error>> {
    let mut f = vec![0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x02];
    f.extend(helper_sos1());
    f.extend_from_slice(&[0x11, 0xFF, 0xD9]);
    let scan = split_jpeg_stream(&f, &MjpegLimits::default(), None)?;
    assert_eq!(
        scan.findings,
        vec![JpegFinding::ShortMarkerSegment {
            frame_index: 0,
            offset: 2,
            marker: 0xC0,
            length: 2,
        }]
    );
    Ok(())
}

#[test]
fn probe_golden_tiling_pinned_literals() -> Result<(), Box<dyn Error>> {
    let mut s = Vec::new();
    s.extend_from_slice(b"AB");
    s.extend(helper_frame(8, 8, &[0x11])); // 28 bytes: 2..30
    s.extend_from_slice(b"--x"); // 30..33
    s.extend(helper_frame(8, 8, &[0xFF, 0x00])); // 29 bytes: 33..62
    s.extend_from_slice(b"Z"); // 62..63
    let scan = split_jpeg_stream(&s, &MjpegLimits::default(), None)?;
    assert_eq!(scan.frames.len(), 2);
    assert_eq!(scan.frames[0].start_offset, 2);
    assert_eq!(scan.frames[0].end_offset, 30);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);

    assert_eq!(scan.frames[1].start_offset, 33);
    assert_eq!(scan.frames[1].end_offset, 62);
    assert!(scan.frames[1].has_eoi);
    assert!(!scan.frames[1].is_truncated);

    assert_eq!(
        scan.omissions,
        vec![
            OmissionSpan {
                start_offset: 0,
                end_offset: 2,
                reason: OmissionReason::GarbageBeforeFirstSoi,
            },
            OmissionSpan {
                start_offset: 30,
                end_offset: 33,
                reason: OmissionReason::GarbageBetweenFrames,
            },
            OmissionSpan {
                start_offset: 62,
                end_offset: 63,
                reason: OmissionReason::TrailingGarbage,
            },
        ]
    );
    assert_eq!(
        scan.findings,
        vec![
            JpegFinding::GarbageBeforeFirstSoi {
                start_offset: 0,
                end_offset: 2,
            },
            JpegFinding::GarbageBetweenFrames {
                preceding_frame_index: 0,
                start_offset: 30,
                end_offset: 33,
            },
            JpegFinding::TrailingGarbage {
                start_offset: 62,
                end_offset: 63,
            },
        ]
    );
    assert_eq!(scan.total_bytes_scanned, 63);
    Ok(())
}

#[test]
fn probe_fill_before_soi_after_garbage() -> Result<(), Box<dyn Error>> {
    let mut s = b"A".to_vec();
    s.extend_from_slice(&[0xFF, 0xFF]);
    s.extend(helper_frame(8, 8, &[0x11]));
    let scan = split_jpeg_stream(&s, &MjpegLimits::default(), None)?;
    assert_eq!(scan.frames.len(), 1);
    assert_eq!(scan.frames[0].start_offset, 1);
    assert_eq!(scan.frames[0].end_offset, 31);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);
    Ok(())
}

#[test]
fn probe_nested_soi_inside_ecs() -> Result<(), Box<dyn Error>> {
    let mut f = vec![0xFF, 0xD8];
    f.extend(helper_sof0(8, 8));
    f.extend(helper_sos1());
    f.extend_from_slice(&[0x11, 0x22]); // ECS, then a nested SOI begins at cut
    let g = helper_frame(8, 8, &[0x33]);
    f.extend_from_slice(&g);
    let scan = split_jpeg_stream(&f, &MjpegLimits::default(), None)?;
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
    Ok(())
}

#[test]
fn probe_stray_ff00_flood_exceeds_marker_limit() -> Result<(), Box<dyn Error>> {
    let mut f = vec![0xFF, 0xD8];
    for _ in 0..1000 {
        f.extend_from_slice(&[0xFF, 0x00]);
    }
    f.extend_from_slice(&[0xFF, 0xD9]);
    let limits = MjpegLimits {
        max_marker_segments_per_frame: 3,
        ..Default::default()
    };
    assert_eq!(
        split_jpeg_stream(&f, &limits, None),
        Err(JpegSplitError::TooManyMarkerSegments {
            frame_index: 0,
            count: 4,
            limit: 3,
        })
    );
    Ok(())
}

#[test]
fn probe_in_frame_garbage_flood_exceeds_marker_limit() -> Result<(), Box<dyn Error>> {
    let mut f = vec![0xFF, 0xD8];
    for _ in 0..1000 {
        f.extend_from_slice(b"x");
        f.extend_from_slice(&[0xFF, 0x00]);
    }
    f.extend_from_slice(&[0xFF, 0xD9]);
    let limits = MjpegLimits {
        max_marker_segments_per_frame: 3,
        ..Default::default()
    };
    assert_eq!(
        split_jpeg_stream(&f, &limits, None),
        Err(JpegSplitError::TooManyMarkerSegments {
            frame_index: 0,
            count: 4,
            limit: 3,
        })
    );
    Ok(())
}

#[test]
fn probe_middle_frame_overflow_resyncs_at_next_soi() -> Result<(), Box<dyn Error>> {
    let a = helper_frame(8, 8, &[0x11]); // 0..28
    let mut s = a.clone();
    s.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE1, 0x01, 0x00]); // 28..34, APP1 declares 256 bytes
    s.extend(helper_frame(8, 8, &[0x22])); // 34..62, complete well-formed frame
    let scan = split_jpeg_stream(&s, &MjpegLimits::default(), None)?;
    assert_eq!(scan.frames.len(), 3);

    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 28);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);

    assert_eq!(scan.frames[1].start_offset, 28);
    assert_eq!(scan.frames[1].end_offset, 34);
    assert!(!scan.frames[1].has_eoi);
    assert!(scan.frames[1].is_truncated);

    assert_eq!(scan.frames[2].start_offset, 34);
    assert_eq!(scan.frames[2].end_offset, 62);
    assert!(scan.frames[2].has_eoi);
    assert!(!scan.frames[2].is_truncated);

    assert_eq!(
        scan.findings,
        vec![
            JpegFinding::MarkerLengthOverflow {
                frame_index: 1,
                offset: 30,
                marker: 0xE1,
                length: 256,
                available: 30,
            },
            JpegFinding::TruncatedFrame {
                frame_index: 1,
                start_offset: 28,
                end_offset: 34,
            },
        ]
    );
    assert!(scan.omissions.is_empty());
    assert_eq!(scan.total_bytes_scanned, 62);
    Ok(())
}

#[test]
fn probe_cut_right_after_marker_code_then_complete_frame() -> Result<(), Box<dyn Error>> {
    // frame1 = FF D8 FF E0 (cut right after the APP0 marker code); the next frame's SOI is read
    // as the length field (0xFFD8), overflows, and resync must start at current_pos without skipping.
    let mut s = helper_frame(8, 8, &[0x11]); // 0..28
    s.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]); // 28..32
    s.extend(helper_frame(8, 8, &[0x22])); // 32..60 complete frame
    let scan = split_jpeg_stream(&s, &MjpegLimits::default(), None)?;
    let spans: Vec<(usize, usize, bool, bool)> = scan
        .frames
        .iter()
        .map(|f| (f.start_offset, f.end_offset, f.has_eoi, f.is_truncated))
        .collect();
    assert_eq!(
        spans,
        vec![
            (0, 28, true, false),
            (28, 32, false, true),
            (32, 60, true, false),
        ],
        "complete frame at 32..60 swallowed"
    );
    Ok(())
}

#[test]
fn probe_cut_after_high_length_byte_then_complete_frame() -> Result<(), Box<dyn Error>> {
    let mut s = helper_frame(8, 8, &[0x11]); // 0..28
    s.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00]); // 28..33, length 0x00FF overflows
    s.extend(helper_frame(8, 8, &[0x22])); // 33..61 complete frame
    let scan = split_jpeg_stream(&s, &MjpegLimits::default(), None)?;
    let spans: Vec<(usize, usize, bool, bool)> = scan
        .frames
        .iter()
        .map(|f| (f.start_offset, f.end_offset, f.has_eoi, f.is_truncated))
        .collect();
    assert_eq!(
        spans,
        vec![
            (0, 28, true, false),
            (28, 33, false, true),
            (33, 61, true, false),
        ],
        "complete frame at 33..61 swallowed"
    );
    Ok(())
}

#[test]
fn probe_garbage_run_counts_toward_marker_limit_kills_f2() -> Result<(), Box<dyn Error>> {
    let lim = MjpegLimits {
        max_marker_segments_per_frame: 3,
        ..Default::default()
    };
    let mut mix = vec![0xFF, 0xD8, b'g', 0xFF, 0x00];
    mix.extend(helper_sof0(8, 8));
    mix.extend(helper_sos1());
    mix.extend_from_slice(&[0x11, 0xFF, 0xD9]);
    assert_eq!(
        split_jpeg_stream(&mix, &lim, None),
        Err(JpegSplitError::TooManyMarkerSegments {
            frame_index: 0,
            count: 4,
            limit: 3,
        })
    );
    Ok(())
}

#[test]
fn probe_p01_eoi_like_bytes_after_stuffing_stay_in_ecs() -> Result<(), Box<dyn Error>> {
    let ecs = [
        0x12, 0xFF, 0x00, 0xD9, 0x34, 0xFF, 0x00, 0xFF, 0x00, 0xD9, 0x56,
    ];
    let f = helper_frame(8, 8, &ecs);
    let scan = split_jpeg_stream(&f, &MjpegLimits::default(), None)?;
    assert_eq!(scan.frames.len(), 1);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 38);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);
    assert_eq!(scan.frames[0].marker_count, 2);
    assert!(scan.findings.is_empty());
    Ok(())
}

#[test]
fn probe_p05_length_below_two() -> Result<(), Box<dyn Error>> {
    let f = [0xFF, 0xD8, 0xFF, 0xFE, 0x00, 0x01, 0xFF, 0xD9];
    let scan = split_jpeg_stream(&f, &MjpegLimits::default(), None)?;
    assert_eq!(scan.frames.len(), 1);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 8);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);
    assert_eq!(
        scan.findings,
        vec![JpegFinding::ZeroLengthMarkerSegment {
            frame_index: 0,
            marker: 0xFE,
            offset: 2,
        }]
    );
    Ok(())
}

#[test]
fn probe_p07a_garbage_between_frames_exact_span() -> Result<(), Box<dyn Error>> {
    let a = helper_frame(8, 8, &[0x11]);
    let b = helper_frame(8, 8, &[0x22]);
    let mut s = a.clone();
    s.extend_from_slice(b"JUNK");
    s.extend_from_slice(&b);
    let scan = split_jpeg_stream(&s, &MjpegLimits::default(), None)?;
    assert_eq!(
        scan.omissions,
        vec![OmissionSpan {
            start_offset: 28,
            end_offset: 32,
            reason: OmissionReason::GarbageBetweenFrames,
        }]
    );
    assert_eq!(scan.frames.len(), 2);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 28);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);
    assert_eq!(scan.frames[1].start_offset, 32);
    assert_eq!(scan.frames[1].end_offset, 60);
    assert!(scan.frames[1].has_eoi);
    assert!(!scan.frames[1].is_truncated);
    assert_eq!(
        scan.findings,
        vec![JpegFinding::GarbageBetweenFrames {
            preceding_frame_index: 0,
            start_offset: 28,
            end_offset: 32,
        }]
    );
    Ok(())
}

#[test]
fn probe_p08_empty_and_tiny_inputs() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        split_jpeg_stream(&[], &MjpegLimits::default(), None),
        Err(JpegSplitError::NoSoi)
    );
    assert_eq!(
        split_jpeg_stream(&[0xFF], &MjpegLimits::default(), None),
        Err(JpegSplitError::NoSoi)
    );
    assert_eq!(
        split_jpeg_stream(&[0xD8, 0xFF], &MjpegLimits::default(), None),
        Err(JpegSplitError::NoSoi)
    );
    Ok(())
}

#[test]
fn probe_p09_max_frames_boundary() -> Result<(), Box<dyn Error>> {
    let one = helper_frame(8, 8, &[0x11]);
    let s = [one.clone(), one.clone(), one.clone()].concat();
    let at = MjpegLimits {
        max_frames: 3,
        ..Default::default()
    };
    assert_eq!(split_jpeg_stream(&s, &at, None)?.frames.len(), 3);
    let below = MjpegLimits {
        max_frames: 2,
        ..Default::default()
    };
    assert_eq!(
        split_jpeg_stream(&s, &below, None),
        Err(JpegSplitError::TooManyFrames { count: 3, limit: 2 })
    );
    Ok(())
}

#[test]
fn probe_p12_minimal_and_zero_body_frames() -> Result<(), Box<dyn Error>> {
    let a = [0xFF, 0xD8, 0xFF, 0xD9];
    let scan_a = split_jpeg_stream(&a, &MjpegLimits::default(), None)?;
    assert_eq!(scan_a.frames.len(), 1);
    assert_eq!(scan_a.frames[0].start_offset, 0);
    assert_eq!(scan_a.frames[0].end_offset, 4);
    assert!(scan_a.frames[0].has_eoi);
    assert!(!scan_a.frames[0].is_truncated);
    assert_eq!(scan_a.frames[0].sof, None);

    let b = [0xFF, 0xD8, 0xFF, 0xD8, 0xFF, 0xD9];
    let scan_b = split_jpeg_stream(&b, &MjpegLimits::default(), None)?;
    assert_eq!(scan_b.frames.len(), 2);
    assert_eq!(scan_b.frames[0].start_offset, 0);
    assert_eq!(scan_b.frames[0].end_offset, 2);
    assert!(!scan_b.frames[0].has_eoi);
    assert!(scan_b.frames[0].is_truncated);
    assert_eq!(scan_b.frames[1].start_offset, 2);
    assert_eq!(scan_b.frames[1].end_offset, 6);
    assert!(scan_b.frames[1].has_eoi);
    assert!(!scan_b.frames[1].is_truncated);
    assert_eq!(
        scan_b.findings,
        vec![JpegFinding::TruncatedFrame {
            frame_index: 0,
            start_offset: 0,
            end_offset: 2,
        }]
    );
    Ok(())
}

#[test]
fn probe_p13_huge_declared_appn_length() -> Result<(), Box<dyn Error>> {
    let mut f = vec![0xFF, 0xD8, 0xFF, 0xE1, 0xFF, 0xFF];
    f.extend_from_slice(&[0u8; 10]);
    let scan_a = split_jpeg_stream(&f, &MjpegLimits::default(), None)?;
    assert_eq!(scan_a.frames.len(), 1);
    assert_eq!(scan_a.frames[0].start_offset, 0);
    assert_eq!(scan_a.frames[0].end_offset, 16);
    assert!(!scan_a.frames[0].has_eoi);
    assert!(scan_a.frames[0].is_truncated);
    assert_eq!(
        scan_a.findings,
        vec![
            JpegFinding::MarkerLengthOverflow {
                frame_index: 0,
                offset: 2,
                marker: 0xE1,
                length: 65535,
                available: 12,
            },
            JpegFinding::TruncatedFrame {
                frame_index: 0,
                start_offset: 0,
                end_offset: 16,
            },
        ]
    );

    let mut g = vec![0xFF, 0xD8, 0xFF, 0xE1, 0xFF, 0xFF];
    g.extend_from_slice(&[0u8; 65533]);
    g.extend_from_slice(&[0xFF, 0xD9]);
    let lim = MjpegLimits {
        max_frame_bytes: 1000,
        ..Default::default()
    };
    assert_eq!(
        split_jpeg_stream(&g, &lim, None),
        Err(JpegSplitError::FrameTooLarge {
            frame_index: 0,
            size: 65539,
            limit: 1000,
        })
    );
    Ok(())
}

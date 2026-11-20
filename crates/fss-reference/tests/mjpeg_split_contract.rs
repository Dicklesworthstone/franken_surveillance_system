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

use fss_core::json_input::{Value, parse as parse_json};
use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_reference::ingest::mjpeg::{
    JpegFinding, JpegFrameSpan, JpegScan, JpegSplitError, MjpegLimits, OmissionReason,
    OmissionSpan, split_jpeg_stream,
};
use fss_reference::{ADP_REPLAY_ROW_ID, DeterministicFaultPrng, ReplayCx};

mod caplog_support;

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

/// Escape characters for safe embedding inside a JSON string literal.
fn escape_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Emits a CAPLOG record whose verdict is exactly `passed` (pass/exit 0, else fail/exit 1).
fn emit_verdict(step: &str, passed: bool, expected: &str, observed: &str, duration_ms: u128) {
    let (verdict, exit_code) = if passed { ("pass", 0) } else { ("fail", 1) };
    emit_caplog(step, verdict, exit_code, expected, observed, duration_ms);
}

// ---------------------------------------------------------------------------
// Exact scan views: ONE comparison feeds both the CAPLOG verdict and the asserts
// ---------------------------------------------------------------------------

/// Every per-frame field this contract pins, compared exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FrameView {
    index: usize,
    start: usize,
    end: usize,
    has_eoi: bool,
    truncated: bool,
    marker_count: usize,
    restart_interval: u16,
    dims: Option<(u16, u16)>,
}

impl FrameView {
    fn of(frame: &JpegFrameSpan) -> Self {
        Self {
            index: frame.frame_index,
            start: frame.start_offset,
            end: frame.end_offset,
            has_eoi: frame.has_eoi,
            truncated: frame.is_truncated,
            marker_count: frame.marker_count,
            restart_interval: frame.restart_interval,
            dims: frame.sof.as_ref().map(|s| (s.width, s.height)),
        }
    }

    fn json(&self) -> String {
        let dims = match self.dims {
            Some((w, h)) => format!("[{w},{h}]"),
            None => "null".to_string(),
        };
        format!(
            r#"{{"index":{},"start":{},"end":{},"has_eoi":{},"truncated":{},"marker_count":{},"restart_interval":{},"dims":{}}}"#,
            self.index,
            self.start,
            self.end,
            self.has_eoi,
            self.truncated,
            self.marker_count,
            self.restart_interval,
            dims
        )
    }
}

/// A frame terminated by EOI, without a DRI segment.
fn complete(
    index: usize,
    start: usize,
    end: usize,
    marker_count: usize,
    dims: Option<(u16, u16)>,
) -> FrameView {
    FrameView {
        index,
        start,
        end,
        has_eoi: true,
        truncated: false,
        marker_count,
        restart_interval: 0,
        dims,
    }
}

/// A frame that never reached EOI, without a DRI segment.
fn truncated(
    index: usize,
    start: usize,
    end: usize,
    marker_count: usize,
    dims: Option<(u16, u16)>,
) -> FrameView {
    FrameView {
        index,
        start,
        end,
        has_eoi: false,
        truncated: true,
        marker_count,
        restart_interval: 0,
        dims,
    }
}

/// Frames, omissions and findings of one scan, compared exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ScanView {
    frames: Vec<FrameView>,
    omissions: Vec<OmissionSpan>,
    findings: Vec<JpegFinding>,
}

impl ScanView {
    fn of(scan: &JpegScan) -> Self {
        Self {
            frames: scan.frames.iter().map(FrameView::of).collect(),
            omissions: scan.omissions.clone(),
            findings: scan.findings.clone(),
        }
    }

    fn json(&self) -> String {
        let frames: Vec<String> = self.frames.iter().map(FrameView::json).collect();
        let omissions: Vec<String> = self
            .omissions
            .iter()
            .map(|o| {
                format!(
                    r#"{{"start":{},"end":{},"reason":"{:?}"}}"#,
                    o.start_offset, o.end_offset, o.reason
                )
            })
            .collect();
        let findings: Vec<String> = self
            .findings
            .iter()
            .map(|f| format!("\"{}\"", escape_json_str(&format!("{f:?}"))))
            .collect();
        format!(
            r#"{{"frames":[{}],"omissions":[{}],"findings":[{}]}}"#,
            frames.join(","),
            omissions.join(","),
            findings.join(",")
        )
    }
}

/// The outcome of one split call, reduced to its exact comparable view.
type Outcome = Result<ScanView, JpegSplitError>;

fn observe(res: &Result<JpegScan, JpegSplitError>) -> Outcome {
    match res {
        Ok(scan) => Ok(ScanView::of(scan)),
        Err(e) => Err(e.clone()),
    }
}

fn outcome_json(outcome: &Outcome) -> String {
    match outcome {
        Ok(view) => view.json(),
        Err(e) => format!(r#"{{"error":"{}"}}"#, escape_json_str(&format!("{e:?}"))),
    }
}

fn named_outcomes_json(named: &[(&str, Outcome)]) -> String {
    let parts: Vec<String> = named
        .iter()
        .map(|(name, outcome)| format!(r#""{name}":{}"#, outcome_json(outcome)))
        .collect();
    format!("{{{}}}", parts.join(","))
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

fn test_cx(label: &str) -> Result<ReplayCx, Box<dyn Error>> {
    let spec = RootAuthoritySpec {
        trace_id: format!("trace:mjpeg-contract-{label}"),
        operation_id: OperationId::parse(format!("operation:mjpeg-contract-{label}"))?,
        principal: format!("operator:mjpeg-contract-{label}"),
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
        .join(format!("test-mjpeg-cx-{label}"));
    Ok(ReplayCx::from_context_authority(&root_auth, &scratch_root)?)
}

// ---------------------------------------------------------------------------
// Step 1: Cooperative cancellation checkpoints
// ---------------------------------------------------------------------------

#[test]
fn test_cancellation_checkpoints() -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let frame = build_test_jpeg(64, 48, 0x77);

    // Pre-cancelled context must be immediately refused
    let cx = match test_cx("cancellation") {
        Ok(cx) => cx,
        Err(e) => {
            let duration_ms = start.elapsed().as_millis().max(1);
            emit_caplog(
                "cancellation_checkpoints",
                "fail",
                1,
                r#"{"cancellation_refused":true,"error":"Err(CancellationRequested)"}"#,
                r#"{"cancellation_refused":false,"error":"test context creation failed"}"#,
                duration_ms,
            );
            return Err(e);
        }
    };
    cx.request_cancellation();

    let limits = MjpegLimits::default();
    let res = split_jpeg_stream(&frame, &limits, Some(&cx));
    let duration_ms = start.elapsed().as_millis().max(1);
    let cancellation_refused = res == Err(JpegSplitError::CancellationRequested);
    let expected = r#"{"cancellation_refused":true,"error":"Err(CancellationRequested)"}"#;
    let observed = format!(
        r#"{{"cancellation_refused":{},"error":"{}"}}"#,
        cancellation_refused,
        escape_json_str(&format!("{res:?}"))
    );
    let passed = observed == expected;
    emit_verdict(
        "cancellation_checkpoints",
        passed,
        expected,
        &observed,
        duration_ms,
    );
    assert_eq!(res, Err(JpegSplitError::CancellationRequested));
    Ok(())
}

#[test]
fn marker_search_across_blocks_preserves_frames_and_observes_cancellation()
-> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    let jpeg = include_bytes!("../../../tests/fixtures/media/jpeg/gray_16x16_flat.jpg");
    let block = 64 * 1024;
    let limits = MjpegLimits::default();
    let mut bytes = vec![0; block - 1];
    bytes.extend_from_slice(jpeg);
    let second_start = bytes.len() + block;
    bytes.resize(second_start, 0xff);
    bytes.extend_from_slice(jpeg);
    let scan = split_jpeg_stream(&bytes, &limits, None)?;
    let spans: Vec<_> = scan
        .frames
        .iter()
        .map(|f| (f.start_offset, f.len()))
        .collect();
    let omissions: Vec<_> = scan
        .omissions
        .iter()
        .map(|o| (o.start_offset, o.end_offset))
        .collect();
    let search = test_cx("search-block")?;
    search.set_cancel_at_checkpoint_occurrence("split_jpeg_stream.find_soi", 3);
    let interrupted = split_jpeg_stream(&bytes, &limits, Some(&search));
    let empty = test_cx("cancel-empty")?;
    empty.request_cancellation();
    let empty_result = split_jpeg_stream(&[], &limits, Some(&empty));

    // JPEG marker fill is allowed immediately before EOI, including inside scan data.
    let mut fill = jpeg[..jpeg.len() - 2].to_vec();
    fill.resize(fill.len() + block * 2, 0xff);
    fill.extend_from_slice(&[0xff, 0xd9]);
    let padded = split_jpeg_stream(&fill, &limits, None)?;
    let padding = test_cx("cancel-fill")?;
    padding.set_cancel_at_checkpoint("split_jpeg_stream.marker_run");
    let fill_result = split_jpeg_stream(&fill, &limits, Some(&padding));
    let record = caplog_support::Record::new("marker_search_across_blocks")
        .check(
            "spans",
            [(block - 1, jpeg.len()), (second_start, jpeg.len())],
            spans,
        )
        .check(
            "omissions",
            [(0, block - 1), (block - 1 + jpeg.len(), second_start)],
            omissions,
        )
        .check(
            "exact_jpegs",
            true,
            scan.frames
                .iter()
                .all(|f| f.slice(&bytes) == Some(jpeg.as_slice())),
        )
        .check("padded_complete", 1_usize, padded.valid_frame_count())
        .check(
            "padded_length",
            Some(fill.len()),
            padded.frames.first().map(JpegFrameSpan::len),
        )
        .check(
            "cancellation_refused",
            [true; 3],
            [interrupted, empty_result, fill_result]
                .map(|r| r == Err(JpegSplitError::CancellationRequested)),
        )
        .check(
            "drained",
            [true; 3],
            [&search, &empty, &padding].map(ReplayCx::is_drain_completed),
        );
    assert!(
        record.emit(started.elapsed().as_millis().max(1)),
        "{}",
        record.observed_json()
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
    let scan_res = split_jpeg_stream(&data, &limits, None);

    let duration_ms = start.elapsed().as_millis().max(1);
    let expected: Outcome = Ok(ScanView {
        frames: vec![complete(0, 0, expected_len, 4, Some((16, 8)))],
        omissions: Vec::new(),
        findings: Vec::new(),
    });
    let observed = observe(&scan_res);
    let passed = observed == expected;
    emit_verdict(
        "edge_case_appn_com_ffd9_shielding",
        passed,
        &outcome_json(&expected),
        &outcome_json(&observed),
        duration_ms,
    );
    assert!(
        passed,
        "appn/com shielding: expected {expected:?}, observed {observed:?}"
    );
    assert_eq!(observed, expected);
    let scan = scan_res?;
    assert_eq!(scan.frames.len(), 1);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, expected_len);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);
    assert_eq!(scan.frames[0].marker_count, 4);
    assert_eq!(scan.findings, Vec::<JpegFinding>::new());
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
    let scan_res = split_jpeg_stream(&f, &limits, None);

    let duration_ms = start.elapsed().as_millis().max(1);
    let expected: Outcome = Ok(ScanView {
        frames: vec![complete(0, 0, 38, 2, Some((8, 8)))],
        omissions: Vec::new(),
        findings: Vec::new(),
    });
    let observed = observe(&scan_res);
    let passed = observed == expected;
    emit_verdict(
        "edge_case_byte_stuffing",
        passed,
        &outcome_json(&expected),
        &outcome_json(&observed),
        duration_ms,
    );
    assert!(
        passed,
        "byte stuffing: expected {expected:?}, observed {observed:?}"
    );
    assert_eq!(observed, expected);
    let scan = scan_res?;
    assert_eq!(scan.frames.len(), 1);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 38);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);
    assert_eq!(scan.frames[0].marker_count, 2);
    assert_eq!(scan.findings, Vec::<JpegFinding>::new());
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
    let scan_res = split_jpeg_stream(&f, &limits, None);

    let duration_ms = start.elapsed().as_millis().max(1);
    let expected: Outcome = Ok(ScanView {
        frames: vec![FrameView {
            index: 0,
            start: 0,
            end: 62,
            has_eoi: true,
            truncated: false,
            marker_count: 3, // DRI, SOF0, SOS1; RSTn inside the ECS are not segments
            restart_interval: 4,
            dims: Some((8, 8)),
        }],
        omissions: Vec::new(),
        findings: Vec::new(),
    });
    let observed = observe(&scan_res);
    let passed = observed == expected;
    emit_verdict(
        "edge_case_restart_markers",
        passed,
        &outcome_json(&expected),
        &outcome_json(&observed),
        duration_ms,
    );
    assert!(
        passed,
        "restart markers: expected {expected:?}, observed {observed:?}"
    );
    assert_eq!(observed, expected);
    let scan = scan_res?;
    assert_eq!(scan.frames.len(), 1);
    assert_eq!(scan.frames[0].start_offset, 0);
    assert_eq!(scan.frames[0].end_offset, 62);
    assert!(scan.frames[0].has_eoi);
    assert!(!scan.frames[0].is_truncated);
    assert_eq!(scan.frames[0].restart_interval, 4);
    assert_eq!(scan.frames[0].marker_count, 3); // DRI, SOF0, SOS1
    assert_eq!(scan.findings, Vec::<JpegFinding>::new());
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
    let scan_res = split_jpeg_stream(&f, &limits, None);

    let duration_ms = start.elapsed().as_millis().max(1);
    let expected: Outcome = Ok(ScanView {
        frames: vec![complete(0, 0, 8, 1, None)],
        omissions: Vec::new(),
        findings: vec![JpegFinding::ZeroLengthMarkerSegment {
            frame_index: 0,
            marker: 0xFE,
            offset: 2,
        }],
    });
    let observed = observe(&scan_res);
    let passed = observed == expected;
    emit_verdict(
        "edge_case_zero_length_segment",
        passed,
        &outcome_json(&expected),
        &outcome_json(&observed),
        duration_ms,
    );
    assert!(
        passed,
        "zero-length segment: expected {expected:?}, observed {observed:?}"
    );
    assert_eq!(observed, expected);
    let scan = scan_res?;
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
    let scan_res = split_jpeg_stream(&f, &limits, None);

    let duration_ms = start.elapsed().as_millis().max(1);
    let expected: Outcome = Ok(ScanView {
        frames: vec![complete(0, 0, 36, 2, Some((16, 8)))],
        omissions: Vec::new(),
        findings: Vec::new(),
    });
    let observed = observe(&scan_res);
    let passed = observed == expected;
    emit_verdict(
        "edge_case_fill_bytes_runs",
        passed,
        &outcome_json(&expected),
        &outcome_json(&observed),
        duration_ms,
    );
    assert!(
        passed,
        "fill bytes: expected {expected:?}, observed {observed:?}"
    );
    assert_eq!(observed, expected);
    let scan = scan_res?;
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
    let scan_res = split_jpeg_stream(&f, &limits, None);

    let duration_ms = start.elapsed().as_millis().max(1);
    let expected: Outcome = Ok(ScanView {
        frames: vec![complete(0, 0, 25, 2, Some((8, 8)))],
        omissions: Vec::new(),
        findings: vec![JpegFinding::ZeroComponents {
            frame_index: 0,
            offset: 2,
        }],
    });
    let observed = observe(&scan_res);
    let passed = observed == expected;
    emit_verdict(
        "edge_case_zero_components",
        passed,
        &outcome_json(&expected),
        &outcome_json(&observed),
        duration_ms,
    );
    assert!(
        passed,
        "zero components: expected {expected:?}, observed {observed:?}"
    );
    assert_eq!(observed, expected);
    let scan = scan_res?;
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
    let (l1, l2, l3) = (f1.len(), f2.len(), f3.len());
    let mut clean_stream = Vec::new();
    clean_stream.extend_from_slice(&f1);
    clean_stream.extend_from_slice(&f2);
    clean_stream.extend_from_slice(&f3);
    let res_clean = split_jpeg_stream(&clean_stream, &limits, None);

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
    let res_trunc = split_jpeg_stream(&trunc_last, &limits, None);

    // Variant 3: Garbage between frames
    let mut junk_stream = Vec::new();
    junk_stream.extend_from_slice(&f1);
    junk_stream.extend_from_slice(b"JUNK1");
    junk_stream.extend_from_slice(&f2);
    junk_stream.extend_from_slice(b"JUNK2");
    junk_stream.extend_from_slice(&f3);
    let res_junk = split_jpeg_stream(&junk_stream, &limits, None);
    let o1_start = f1.len();
    let o1_end = f1.len() + 5;
    let o2_start = o1_end + f2.len();
    let o2_end = o2_start + 5;

    // Variant 4: Zero length stream
    let res_zero = split_jpeg_stream(&[], &limits, None);

    // Variant 5: Dimension change across frames
    let mut dim_stream = Vec::new();
    dim_stream.extend_from_slice(&f1); // 16x16
    dim_stream.extend_from_slice(&f3); // 64x48
    let res_dim = split_jpeg_stream(&dim_stream, &limits, None);

    let duration_ms = start.elapsed().as_millis().max(1);
    // DQT, SOF0 and SOS are the three marker segments of every build_test_jpeg frame.
    let expected: Vec<(&str, Outcome)> = vec![
        (
            "clean",
            Ok(ScanView {
                frames: vec![
                    complete(0, 0, l1, 3, Some((16, 16))),
                    complete(1, l1, l1 + l2, 3, Some((32, 24))),
                    complete(2, l1 + l2, l1 + l2 + l3, 3, Some((64, 48))),
                ],
                omissions: Vec::new(),
                findings: Vec::new(),
            }),
        ),
        (
            "truncated_last",
            Ok(ScanView {
                frames: vec![
                    complete(0, 0, l1, 3, Some((16, 16))),
                    complete(1, l1, l1 + l2, 3, Some((32, 24))),
                    truncated(2, f3_cut_start, trunc_last_len, 2, Some((64, 48))),
                ],
                omissions: Vec::new(),
                findings: vec![JpegFinding::TruncatedFrame {
                    frame_index: 2,
                    start_offset: f3_cut_start,
                    end_offset: trunc_last_len,
                }],
            }),
        ),
        (
            "garbage_between",
            Ok(ScanView {
                frames: vec![
                    complete(0, 0, l1, 3, Some((16, 16))),
                    complete(1, o1_end, o2_start, 3, Some((32, 24))),
                    complete(2, o2_end, o2_end + l3, 3, Some((64, 48))),
                ],
                omissions: vec![
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
                ],
                findings: vec![
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
                ],
            }),
        ),
        ("zero_length", Err(JpegSplitError::NoSoi)),
        (
            "dimension_change",
            Ok(ScanView {
                frames: vec![
                    complete(0, 0, l1, 3, Some((16, 16))),
                    complete(1, l1, l1 + l3, 3, Some((64, 48))),
                ],
                omissions: Vec::new(),
                findings: Vec::new(),
            }),
        ),
    ];
    let observed: Vec<(&str, Outcome)> = vec![
        ("clean", observe(&res_clean)),
        ("truncated_last", observe(&res_trunc)),
        ("garbage_between", observe(&res_junk)),
        ("zero_length", observe(&res_zero)),
        ("dimension_change", observe(&res_dim)),
    ];
    let passed = observed == expected;
    emit_verdict(
        "synthetic_stream_variants",
        passed,
        &named_outcomes_json(&expected),
        &named_outcomes_json(&observed),
        duration_ms,
    );
    assert!(
        passed,
        "synthetic variants: expected {expected:?}, observed {observed:?}"
    );
    assert_eq!(observed, expected);

    // Variant 1 asserts
    let scan_clean = res_clean?;
    assert_eq!(scan_clean.frame_count(), 3);
    assert_eq!(scan_clean.valid_frame_count(), 3);
    assert!(!scan_clean.has_truncation());
    assert!(!scan_clean.has_omissions());
    assert!(scan_clean.findings.is_empty());

    // Variant 2 asserts
    let scan_trunc = res_trunc?;
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

    // Variant 3 asserts
    let scan_junk = res_junk?;
    assert_eq!(scan_junk.frame_count(), 3);
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

    // Variant 4 asserts
    assert_eq!(res_zero, Err(JpegSplitError::NoSoi));

    // Variant 5 asserts
    let scan_dim = res_dim?;
    assert_eq!(scan_dim.frame_count(), 2);
    assert_eq!(
        scan_dim.frames[0].sof.as_ref().map(|s| (s.width, s.height)),
        Some((16, 16))
    );
    assert_eq!(
        scan_dim.frames[1].sof.as_ref().map(|s| (s.width, s.height)),
        Some((64, 48))
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Step 9: Fixture manifest equality and delegated JPEG fixtures
// ---------------------------------------------------------------------------

fn manifest_field<'a>(row: &'a Value, key: &str) -> Option<&'a Value> {
    row.object()?.get(key)
}

fn manifest_number(row: &Value, key: &str) -> Result<usize, String> {
    manifest_field(row, key)
        .and_then(|v| match v {
            Value::Number(n) => n.parse().ok(),
            _ => None,
        })
        .ok_or_else(|| format!("missing or invalid {key}"))
}

fn manifest_text<'a>(row: &'a Value, key: &str) -> Result<&'a str, String> {
    manifest_field(row, key)
        .and_then(Value::text)
        .ok_or_else(|| format!("missing {key}"))
}

fn check_recorded_fixture(
    dir: &std::path::Path,
    jpeg: bool,
    row: &Value,
) -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let name = manifest_text(row, "name")?;
    let bytes = fs::read(dir.join(name))?;
    let file_size = manifest_number(row, "file_size")?;
    let file_sha = manifest_text(row, "file_sha256")?;
    let frame_rows = if jpeg {
        std::slice::from_ref(row)
    } else {
        manifest_field(row, "frames")
            .and_then(Value::array)
            .ok_or("missing frames")?
    };
    let frame_count = if jpeg {
        1
    } else {
        manifest_number(row, "frame_count")?
    };
    let truncated_last =
        manifest_field(row, "variant").and_then(Value::text) == Some("truncated_last");
    let mut spans = Vec::new();
    let mut dimensions = Vec::new();
    let mut digests = Vec::new();
    let mut completion = Vec::new();
    let mut findings = Vec::new();
    let mut omissions = Vec::new();
    let mut previous_end = 0;
    for (i, frame) in frame_rows.iter().enumerate() {
        let (index, offset, length, hash) = if jpeg {
            (0, 0, file_size, file_sha)
        } else {
            (
                manifest_number(frame, "index")?,
                manifest_number(frame, "offset")?,
                manifest_number(frame, "length")?,
                manifest_text(frame, "frame_sha256")?,
            )
        };
        if i != index || offset < previous_end {
            return Err(format!("{name}: unordered manifest frame {index}").into());
        }
        if offset > previous_end {
            omissions.push((previous_end, offset));
            let gap = if i == 0 {
                JpegFinding::GarbageBeforeFirstSoi {
                    start_offset: 0,
                    end_offset: offset,
                }
            } else {
                JpegFinding::GarbageBetweenFrames {
                    preceding_frame_index: i - 1,
                    start_offset: previous_end,
                    end_offset: offset,
                }
            };
            findings.push(gap);
        }
        previous_end = offset.checked_add(length).ok_or("invalid manifest span")?;
        let truncated = truncated_last && i + 1 == frame_rows.len();
        if truncated {
            findings.push(JpegFinding::TruncatedFrame {
                frame_index: i,
                start_offset: offset,
                end_offset: previous_end,
            });
        }
        spans.push((index, (offset, length)));
        dimensions.push(Some((
            manifest_number(frame, "width")?,
            manifest_number(frame, "height")?,
        )));
        digests.push(hash);
        completion.push((!truncated, truncated));
    }
    if !spans.is_empty() && previous_end < file_size {
        omissions.push((previous_end, file_size));
        findings.push(JpegFinding::TrailingGarbage {
            start_offset: previous_end,
            end_offset: file_size,
        });
    }

    let limits = MjpegLimits::default();
    let result = split_jpeg_stream(&bytes, &limits, None);
    let frames = result
        .as_ref()
        .map_or(&[][..], |scan| scan.frames.as_slice());
    let observed_findings = result
        .as_ref()
        .map_or(&[][..], |scan| scan.findings.as_slice());
    let mut record = caplog_support::Record::new(&format!("fixture_{name}"))
        .check("file_bytes", file_size, bytes.len())
        .check("file_sha256", file_sha, sha256_hex(&bytes))
        .check("frame_count", frame_count, frames.len())
        .check(
            "scanned_bytes",
            (file_size > 0).then_some(file_size),
            result.as_ref().ok().map(|scan| scan.total_bytes_scanned),
        )
        .check(
            "omission_spans",
            omissions,
            result
                .iter()
                .flat_map(|scan| {
                    scan.omissions
                        .iter()
                        .map(|o| (o.start_offset, o.end_offset))
                })
                .collect::<Vec<_>>(),
        )
        .check(
            "spans",
            spans,
            frames
                .iter()
                .map(|f| (f.frame_index, (f.start_offset, f.len())))
                .collect::<Vec<_>>(),
        )
        .check(
            "dimensions",
            dimensions,
            frames
                .iter()
                .map(|f| {
                    f.sof
                        .as_ref()
                        .map(|s| (usize::from(s.width), usize::from(s.height)))
                })
                .collect::<Vec<_>>(),
        )
        .check(
            "frame_sha256",
            digests,
            frames
                .iter()
                .map(|f| f.slice(&bytes).map(sha256_hex))
                .collect::<Vec<_>>(),
        )
        .check(
            "eoi_truncated",
            completion,
            frames
                .iter()
                .map(|f| (f.has_eoi, f.is_truncated))
                .collect::<Vec<_>>(),
        )
        .check(
            "findings",
            findings
                .iter()
                .map(|f| format!("{f:?}"))
                .collect::<Vec<_>>(),
            observed_findings
                .iter()
                .map(|f| format!("{f:?}"))
                .collect::<Vec<_>>(),
        )
        .check(
            "error",
            (file_size == 0).then_some("NoSoi"),
            result.as_ref().err().map(|e| format!("{e:?}")),
        )
        .check(
            "repeatable",
            true,
            result == split_jpeg_stream(&bytes, &limits, None),
        );
    if jpeg {
        record = record
            .check(
                "components",
                manifest_number(row, "channels")?,
                frames
                    .first()
                    .and_then(|f| f.sof.as_ref())
                    .map(|sof| sof.components),
            )
            .check(
                "restart_interval",
                manifest_number(row, "restart_interval")?,
                frames.first().map(|f| f.restart_interval),
            );
    }
    assert!(
        record.emit(start.elapsed().as_millis().max(1)),
        "fixture {name}: {}",
        record.observed_json()
    );
    Ok(())
}

#[test]
fn test_fixture_manifest_equality() -> Result<(), Box<dyn Error>> {
    let media = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/media");
    for (family, extension) in [("jpeg", "jpg"), ("mjpeg", "mjpeg")] {
        let dir = media.join(family);
        let manifest = parse_json(&fs::read_to_string(dir.join("fixture_manifest.json"))?)?;
        assert_eq!(
            manifest_text(&manifest, "schema")?,
            format!("fss.{family}_fixture_manifest.v1")
        );
        let fixtures = manifest_field(&manifest, "fixtures")
            .and_then(Value::array)
            .ok_or("missing fixture rows")?;
        let mut listed: Vec<&str> = fixtures
            .iter()
            .map(|f| manifest_text(f, "name"))
            .collect::<Result<_, _>>()?;
        listed.sort_unstable();
        let mut present = Vec::new();
        for path in fs::read_dir(&dir)? {
            let path = path?.path();
            if path.extension().is_some_and(|ext| ext == extension) {
                present.push(
                    path.file_name()
                        .and_then(|s| s.to_str())
                        .ok_or("non-UTF8 fixture name")?
                        .to_owned(),
                );
            }
        }
        present.sort_unstable();
        assert!(!listed.is_empty());
        assert_eq!(
            listed, present,
            "{family} manifest and fixture directory differ"
        );
        for fixture in fixtures {
            check_recorded_fixture(&dir, family == "jpeg", fixture)?;
        }
    }
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
    let restart = jpeg_dir.join("rgb_64x48_restart_ri5.jpg");

    let limits = MjpegLimits::default();
    let mut fixtures_verified = 0usize;
    let mut fixtures_skipped = 0usize;
    let mut skip_reasons = Vec::new();
    let mut failure_reasons = Vec::new();

    // Check 1: rgb_64x48_app_com_ffd9.jpg
    if app_com.is_file() {
        match fs::read(&app_com) {
            Ok(bytes) => match split_jpeg_stream(&bytes, &limits, None) {
                Ok(scan) => {
                    let mut ok = true;
                    if scan.frame_count() != 1 {
                        failure_reasons.push(format!(
                            "app_com: frame_count is {} != 1",
                            scan.frame_count()
                        ));
                        ok = false;
                    }
                    match scan.frames.first().and_then(|f| f.sof.as_ref()) {
                        Some(sof) => {
                            if sof.width != 64 || sof.height != 48 {
                                failure_reasons.push(format!(
                                    "app_com: dim ({},{}) != (64,48)",
                                    sof.width, sof.height
                                ));
                                ok = false;
                            }
                        }
                        None => {
                            failure_reasons.push("app_com: missing SOF".to_string());
                            ok = false;
                        }
                    }
                    if ok {
                        fixtures_verified += 1;
                    }
                }
                Err(e) => {
                    failure_reasons.push(format!("app_com: split error {e:?}"));
                }
            },
            Err(e) => {
                failure_reasons.push(format!("app_com: read error {e}"));
            }
        }
    } else {
        fixtures_skipped += 1;
        skip_reasons.push("rgb_64x48_app_com_ffd9.jpg not found on disk".to_string());
    }

    // Check 2: rgb_64x48_restart_ri5.jpg (the restart fixture fss-2h5zq.5 produces).
    // Expected values are derived from the committed file bytes and agree with the
    // independent baseline decoder in media_fixture_jpeg_contract.rs (DRI 5, 12 MCUs
    // decoded as [5, 5, 2] per entropy-coded segment, RST0 at 736, RST1 at 865):
    // 917 bytes; APP0@2, DQT@20, SOF0@154, DRI@173, DHT@179, SOS@599 = 6 marker
    // segments; SOS header ends at 613; RSTn inside the entropy-coded data are not
    // counted by the splitter; EOI@915 ends the frame at 917.
    if restart.is_file() {
        match fs::read(&restart) {
            Ok(bytes) => match split_jpeg_stream(&bytes, &limits, None) {
                Ok(scan) => {
                    let mut ok = true;
                    if scan.frame_count() != 1 {
                        failure_reasons.push(format!(
                            "restart: frame_count is {} != 1",
                            scan.frame_count()
                        ));
                        ok = false;
                    }
                    if let Some(f0) = scan.frames.first() {
                        if f0.restart_interval != 5 {
                            failure_reasons.push(format!(
                                "restart: restart_interval is {} != 5",
                                f0.restart_interval
                            ));
                            ok = false;
                        }
                        let span = (
                            f0.start_offset,
                            f0.end_offset,
                            f0.has_eoi,
                            f0.is_truncated,
                            f0.marker_count,
                        );
                        if span != (0, 917, true, false, 6) {
                            failure_reasons.push(format!(
                                "restart: (start, end, has_eoi, is_truncated, marker_count) {span:?} != (0, 917, true, false, 6)"
                            ));
                            ok = false;
                        }
                        if let Some(sof) = f0.sof.as_ref()
                            && (sof.components != 3 || sof.precision != 8)
                        {
                            failure_reasons.push(format!(
                                "restart: components/precision ({},{}) != (3,8)",
                                sof.components, sof.precision
                            ));
                            ok = false;
                        }
                        match f0.sof.as_ref() {
                            Some(sof) => {
                                if sof.width != 64 || sof.height != 48 {
                                    failure_reasons.push(format!(
                                        "restart: dim ({},{}) != (64,48)",
                                        sof.width, sof.height
                                    ));
                                    ok = false;
                                }
                            }
                            None => {
                                failure_reasons.push("restart: missing SOF".to_string());
                                ok = false;
                            }
                        }
                    } else {
                        failure_reasons.push("restart: missing frame 0".to_string());
                        ok = false;
                    }
                    if !scan.findings.is_empty() || !scan.omissions.is_empty() {
                        failure_reasons.push(format!(
                            "restart: findings {:?} / omissions {:?} must both be empty",
                            scan.findings, scan.omissions
                        ));
                        ok = false;
                    }
                    // Byte-level cross-check against the decoder's known facts: exactly two
                    // restart markers, RST0 at 736 and RST1 at 865, both strictly between the
                    // SOS header end (613) and EOI (915).
                    let rst_positions: Vec<(usize, u8)> = bytes
                        .windows(2)
                        .enumerate()
                        .filter(|(_, w)| w[0] == 0xFF && (0xD0..=0xD7).contains(&w[1]))
                        .map(|(i, w)| (i, w[1]))
                        .collect();
                    if bytes.len() != 917
                        || rst_positions != vec![(736, 0xD0), (865, 0xD1)]
                        || bytes.get(915..917) != Some(&[0xFF, 0xD9][..])
                        || !rst_positions.iter().all(|&(i, _)| i > 613 && i < 915)
                    {
                        failure_reasons.push(format!(
                            "restart: file bytes len {} rst {rst_positions:?} != 917 / [(736, 0xD0), (865, 0xD1)] with EOI at 915",
                            bytes.len()
                        ));
                        ok = false;
                    }
                    if ok {
                        fixtures_verified += 1;
                    }
                }
                Err(e) => {
                    failure_reasons.push(format!("restart: split error {e:?}"));
                }
            },
            Err(e) => {
                failure_reasons.push(format!("restart: read error {e}"));
            }
        }
    } else {
        fixtures_skipped += 1;
        skip_reasons.push("rgb_64x48_restart_ri5.jpg not found on disk".to_string());
    }

    let duration_ms = start.elapsed().as_millis().max(1);
    // One constant: what a full pass looks like, whatever was observed.
    let expected = r#"{"fixtures_verified":2,"fixtures_skipped":0,"failures":0}"#;

    // Both files arrive with fss-2h5zq.5. When NEITHER is on disk the step is an explicit skip
    // (never a pass). A partial set (one present, one missing) is a failure, not a skip.
    if fixtures_skipped == 2 && failure_reasons.is_empty() {
        let observed = format!(
            r#"{{"fixtures_verified":{fixtures_verified},"fixtures_skipped":{fixtures_skipped},"failures":0,"reason":"fixtures from fss-2h5zq.5 not present","missing":"{}"}}"#,
            escape_json_str(&skip_reasons.join("; "))
        );
        emit_caplog(
            "delegated_jpeg_fixtures",
            "skip",
            0,
            expected,
            &observed,
            duration_ms,
        );
        return Ok(());
    }

    let passed = failure_reasons.is_empty() && fixtures_skipped == 0 && fixtures_verified == 2;
    // The record carries exactly the compared values: its verdict equals `passed`.
    caplog_support::Record::new("delegated_jpeg_fixtures")
        .check("fixtures_verified", 2_usize, fixtures_verified)
        .check("fixtures_skipped", 0_usize, fixtures_skipped)
        .check(
            "failure_reasons",
            Vec::<String>::new(),
            failure_reasons.clone(),
        )
        .check("missing", Vec::<String>::new(), skip_reasons.clone())
        .emit(duration_ms);

    assert!(
        passed,
        "delegated fixtures: verified {fixtures_verified}, missing {skip_reasons:?}, failures {failure_reasons:?}"
    );
    assert!(
        failure_reasons.is_empty(),
        "Delegated JPEG fixtures verification failures: {failure_reasons:?}"
    );
    assert_eq!(fixtures_skipped, 0, "partial fixture set: {skip_reasons:?}");
    assert_eq!(fixtures_verified, 2);
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
    let scan_res = split_jpeg_stream(&stream, &limits, None);
    let duration_ms = start.elapsed().as_millis().max(1);

    let expected: Outcome = Ok(ScanView {
        frames: vec![
            complete(0, 4, 4 + len1, 3, Some((16, 16))),
            complete(1, 7 + len1, 7 + len1 + len2, 3, Some((32, 24))),
        ],
        omissions: vec![
            OmissionSpan {
                start_offset: 0,
                end_offset: 4,
                reason: OmissionReason::GarbageBeforeFirstSoi,
            },
            OmissionSpan {
                start_offset: 4 + len1,
                end_offset: 7 + len1,
                reason: OmissionReason::GarbageBetweenFrames,
            },
            OmissionSpan {
                start_offset: 7 + len1 + len2,
                end_offset: total_len,
                reason: OmissionReason::TrailingGarbage,
            },
        ],
        findings: vec![
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
        ],
    });
    let observed = observe(&scan_res);
    let passed = observed == expected;
    emit_verdict(
        "gauntlet_omissions_and_garbage",
        passed,
        &outcome_json(&expected),
        &outcome_json(&observed),
        duration_ms,
    );
    assert!(
        passed,
        "omissions and garbage: expected {expected:?}, observed {observed:?}"
    );
    assert_eq!(observed, expected);
    let scan = scan_res?;
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
    let scan_res = split_jpeg_stream(&data, &limits, None);
    let duration_ms = start.elapsed().as_millis().max(1);

    let expected: Outcome = Ok(ScanView {
        // marker_count 5: garbage run, stray FF00, short SOF, zero-height SOF, DNL. The
        // zero-height SOF (width 16, height 0) is the first well-formed SOF, so it is recorded.
        frames: vec![complete(0, 0, 35, 5, Some((16, 0)))],
        omissions: Vec::new(),
        findings: vec![
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
        ],
    });
    let observed = observe(&scan_res);
    let passed = observed == expected;
    emit_verdict(
        "gauntlet_in_frame_anomalies",
        passed,
        &outcome_json(&expected),
        &outcome_json(&observed),
        duration_ms,
    );
    assert!(
        passed,
        "in-frame anomalies: expected {expected:?}, observed {observed:?}"
    );
    assert_eq!(observed, expected);
    let scan = scan_res?;
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
    let scan_in = split_jpeg_stream(&frame, &exact_input_limits, None);

    let too_small_input_limits = MjpegLimits {
        max_input_bytes: frame_len - 1,
        ..MjpegLimits::default()
    };
    let res_in = split_jpeg_stream(&frame, &too_small_input_limits, None);

    // 12.2 max_frame_bytes boundary
    let exact_frame_limits = MjpegLimits {
        max_frame_bytes: frame_len,
        ..MjpegLimits::default()
    };
    let scan_fr = split_jpeg_stream(&frame, &exact_frame_limits, None);

    let too_small_frame_limits = MjpegLimits {
        max_frame_bytes: frame_len - 1,
        ..MjpegLimits::default()
    };
    let res_fr = split_jpeg_stream(&frame, &too_small_frame_limits, None);

    // 12.3 max_dimension boundary on standard frame
    let exact_dim_limits = MjpegLimits {
        max_dimension: 64,
        ..MjpegLimits::default()
    };
    let scan_dim = split_jpeg_stream(&frame, &exact_dim_limits, None);

    let too_small_dim_limits = MjpegLimits {
        max_dimension: 63,
        ..MjpegLimits::default()
    };
    let res_dim = split_jpeg_stream(&frame, &too_small_dim_limits, None);

    // Height dimension boundary
    let too_small_height_limits = MjpegLimits {
        max_dimension: 47,
        ..MjpegLimits::default()
    };
    let res_height = split_jpeg_stream(&frame, &too_small_height_limits, None);

    // 12.4 Oversize dimensions (Kills M7)
    let wide_frame = helper_frame(16385, 8, &[0x11]);
    let res_wide = split_jpeg_stream(&wide_frame, &MjpegLimits::default(), None);

    let tall_frame = helper_frame(8, 16385, &[0x11]);
    let res_tall = split_jpeg_stream(&tall_frame, &MjpegLimits::default(), None);

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

    let duration_ms = start.elapsed().as_millis().max(1);
    let one_frame = || -> Outcome {
        Ok(ScanView {
            frames: vec![complete(0, 0, frame_len, 3, Some((64, 48)))],
            omissions: Vec::new(),
            findings: Vec::new(),
        })
    };
    let expected: Vec<(&str, Outcome)> = vec![
        ("max_input_bytes_exact", one_frame()),
        (
            "max_input_bytes_minus_1",
            Err(JpegSplitError::InputOversized {
                size: frame_len,
                limit: frame_len - 1,
            }),
        ),
        ("max_frame_bytes_exact", one_frame()),
        (
            "max_frame_bytes_minus_1",
            Err(JpegSplitError::FrameTooLarge {
                frame_index: 0,
                size: frame_len,
                limit: frame_len - 1,
            }),
        ),
        ("max_dimension_exact", one_frame()),
        (
            "max_dimension_63",
            Err(JpegSplitError::DimensionLimit {
                width: 64,
                height: 48,
                max_dimension: 63,
            }),
        ),
        (
            "max_dimension_47",
            Err(JpegSplitError::DimensionLimit {
                width: 64,
                height: 48,
                max_dimension: 47,
            }),
        ),
        (
            "width_16385",
            Err(JpegSplitError::DimensionLimit {
                width: 16385,
                height: 8,
                max_dimension: 16384,
            }),
        ),
        (
            "height_16385",
            Err(JpegSplitError::DimensionLimit {
                width: 8,
                height: 16385,
                max_dimension: 16384,
            }),
        ),
        (
            "max_frames_1",
            Err(JpegSplitError::TooManyFrames { count: 2, limit: 1 }),
        ),
    ];
    let observed: Vec<(&str, Outcome)> = vec![
        ("max_input_bytes_exact", observe(&scan_in)),
        ("max_input_bytes_minus_1", observe(&res_in)),
        ("max_frame_bytes_exact", observe(&scan_fr)),
        ("max_frame_bytes_minus_1", observe(&res_fr)),
        ("max_dimension_exact", observe(&scan_dim)),
        ("max_dimension_63", observe(&res_dim)),
        ("max_dimension_47", observe(&res_height)),
        ("width_16385", observe(&res_wide)),
        ("height_16385", observe(&res_tall)),
        ("max_frames_1", observe(&res_frames)),
    ];
    let passed = observed == expected;
    emit_verdict(
        "limits_enforcement_boundaries",
        passed,
        &named_outcomes_json(&expected),
        &named_outcomes_json(&observed),
        duration_ms,
    );
    assert!(
        passed,
        "limits boundaries: expected {expected:?}, observed {observed:?}"
    );
    assert_eq!(observed, expected);

    assert_eq!(scan_in?.frames.len(), 1);
    assert_eq!(
        res_in,
        Err(JpegSplitError::InputOversized {
            size: frame_len,
            limit: frame_len - 1,
        })
    );

    assert_eq!(scan_fr?.frames.len(), 1);
    assert_eq!(
        res_fr,
        Err(JpegSplitError::FrameTooLarge {
            frame_index: 0,
            size: frame_len,
            limit: frame_len - 1,
        })
    );

    assert_eq!(scan_dim?.frames.len(), 1);
    assert_eq!(
        res_dim,
        Err(JpegSplitError::DimensionLimit {
            width: 64,
            height: 48,
            max_dimension: 63,
        })
    );

    assert_eq!(
        res_height,
        Err(JpegSplitError::DimensionLimit {
            width: 64,
            height: 48,
            max_dimension: 47,
        })
    );

    assert_eq!(
        res_wide,
        Err(JpegSplitError::DimensionLimit {
            width: 16385,
            height: 8,
            max_dimension: 16384,
        })
    );

    assert_eq!(
        res_tall,
        Err(JpegSplitError::DimensionLimit {
            width: 8,
            height: 16385,
            max_dimension: 16384,
        })
    );

    assert_eq!(
        res_frames,
        Err(JpegSplitError::TooManyFrames { count: 2, limit: 1 })
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
    let scan_res = split_jpeg_stream(&stream, &limits, None);
    let duration_ms = start.elapsed().as_millis().max(1);

    let available = stream.len().saturating_sub(f2_start + 4);
    let expected: Outcome = Ok(ScanView {
        frames: vec![
            complete(0, 0, f2_start, 3, Some((16, 16))),
            // APP0 is counted before its length is found to overflow; no SOF was reached.
            truncated(1, f2_start, f3_start, 1, None),
            complete(2, f3_start, total_len, 3, Some((16, 16))),
        ],
        omissions: Vec::new(),
        findings: vec![
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
        ],
    });
    let observed = observe(&scan_res);
    let passed = observed == expected;
    emit_verdict(
        "gauntlet_middle_frame_resync",
        passed,
        &outcome_json(&expected),
        &outcome_json(&observed),
        duration_ms,
    );
    assert!(
        passed,
        "middle frame resync: expected {expected:?}, observed {observed:?}"
    );
    assert_eq!(observed, expected);
    let scan = scan_res?;
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

    let scan_3 = split_jpeg_stream(&frame_exact_3, &limits, None);

    // 14.2 Exceeding boundary: exactly 4 markers against limit 3 MUST FAIL with count 4
    let mut frame_exceed_4 = Vec::new();
    frame_exceed_4.extend_from_slice(&[0xFF, 0xD8]);
    for _ in 0..4 {
        frame_exceed_4.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x04, 0xAA, 0xBB]);
    }
    frame_exceed_4.extend_from_slice(&[0xFF, 0xD9]);

    let res_exceed = split_jpeg_stream(&frame_exceed_4, &limits, None);

    // 14.3 In-frame garbage run counted toward marker limit (Kills M5)
    // Stream has: SOI, 1 garbage byte (count 1), 1 stray 0xFF00 (count 2), SOF0 (count 3), SOS1 (count 4 -> error!)
    let mut mix = vec![0xFF, 0xD8, b'g', 0xFF, 0x00];
    mix.extend(helper_sof0(8, 8));
    mix.extend(helper_sos1());
    mix.extend_from_slice(&[0x11, 0xFF, 0xD9]);

    let res_garb = split_jpeg_stream(&mix, &limits, None);

    let duration_ms = start.elapsed().as_millis().max(1);
    let expected: Vec<(&str, Outcome)> = vec![
        (
            "cap_boundary_exact_3",
            Ok(ScanView {
                frames: vec![complete(0, 0, frame_exact_3.len(), 3, None)],
                omissions: Vec::new(),
                findings: Vec::new(),
            }),
        ),
        (
            "exceed_4",
            Err(JpegSplitError::TooManyMarkerSegments {
                frame_index: 0,
                count: 4,
                limit: 3,
            }),
        ),
        (
            "garbage_run_counted",
            Err(JpegSplitError::TooManyMarkerSegments {
                frame_index: 0,
                count: 4,
                limit: 3,
            }),
        ),
    ];
    let observed: Vec<(&str, Outcome)> = vec![
        ("cap_boundary_exact_3", observe(&scan_3)),
        ("exceed_4", observe(&res_exceed)),
        ("garbage_run_counted", observe(&res_garb)),
    ];
    let passed = observed == expected;
    emit_verdict(
        "gauntlet_flood_limits",
        passed,
        &named_outcomes_json(&expected),
        &named_outcomes_json(&observed),
        duration_ms,
    );
    assert!(
        passed,
        "flood limits: expected {expected:?}, observed {observed:?}"
    );
    assert_eq!(observed, expected);

    let scan_3_val = scan_3?;
    assert_eq!(scan_3_val.frames.len(), 1);
    assert_eq!(scan_3_val.frames[0].marker_count, 3);
    assert!(scan_3_val.frames[0].has_eoi);

    assert_eq!(
        res_exceed,
        Err(JpegSplitError::TooManyMarkerSegments {
            frame_index: 0,
            count: 4,
            limit: 3,
        })
    );

    assert_eq!(
        res_garb,
        Err(JpegSplitError::TooManyMarkerSegments {
            frame_index: 0,
            count: 4,
            limit: 3,
        })
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

    // Floor pinned below the observed 8874/10000 successful scans for this seed and template.
    const MIN_SUCCESSFUL_SCANS: usize = 8_000;
    // Every error a splitter call without a ReplayCx may legitimately return for these limits.
    const ALLOWED_ERROR_KINDS: [&str; 7] = [
        "NoSoi",
        "MarkerLengthOverflow",
        "TooManyFrames",
        "FrameTooLarge",
        "TooManyMarkerSegments",
        "DimensionLimit",
        "InputOversized",
    ];

    let mut successful_scans = 0usize;
    let mut observed_panics = 0usize;
    let mut invariant_violations = 0usize;
    let mut allowed_errors = 0usize;
    let mut unexpected_errors = 0usize;
    let mut unexpected_samples: Vec<String> = Vec::new();
    let iterations = 10_000usize;

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
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            split_jpeg_stream(&mutated, &limits, None)
        }));

        match outcome {
            Err(_) => {
                observed_panics += 1;
            }
            Ok(Ok(scan)) => {
                successful_scans += 1;

                // Invariant checks on every Ok
                if scan.total_bytes_scanned != mutated.len() {
                    invariant_violations += 1;
                }

                // 1. Validate frames: ordered, non-overlapping, within bounds
                let mut prev_frame_end = 0;
                for (idx, frame) in scan.frames.iter().enumerate() {
                    if frame.frame_index != idx
                        || frame.start_offset < prev_frame_end
                        || frame.start_offset > frame.end_offset
                        || frame.end_offset > scan.total_bytes_scanned
                    {
                        invariant_violations += 1;
                    }
                    prev_frame_end = frame.end_offset;
                }

                // 2. Validate omissions: ordered, non-overlapping, within bounds
                let mut prev_om_end = 0;
                for om in &scan.omissions {
                    if om.start_offset < prev_om_end
                        || om.start_offset >= om.end_offset
                        || om.end_offset > scan.total_bytes_scanned
                    {
                        invariant_violations += 1;
                    }
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
                let mut tiling_ok = true;
                for (s, e) in all_spans {
                    if s != cur_offset {
                        tiling_ok = false;
                        break;
                    }
                    cur_offset = e;
                }
                if !tiling_ok || cur_offset != scan.total_bytes_scanned {
                    invariant_violations += 1;
                }

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
                    if off > scan.total_bytes_scanned {
                        invariant_violations += 1;
                    }
                }
            }
            Ok(Err(err)) => {
                let kind = match &err {
                    JpegSplitError::NoSoi => Some("NoSoi"),
                    JpegSplitError::MarkerLengthOverflow { .. } => Some("MarkerLengthOverflow"),
                    JpegSplitError::TooManyFrames { .. } => Some("TooManyFrames"),
                    JpegSplitError::FrameTooLarge { .. } => Some("FrameTooLarge"),
                    JpegSplitError::TooManyMarkerSegments { .. } => Some("TooManyMarkerSegments"),
                    JpegSplitError::DimensionLimit { .. } => Some("DimensionLimit"),
                    JpegSplitError::InputOversized { .. } => Some("InputOversized"),
                    _ => None,
                };
                match kind {
                    Some(k) if ALLOWED_ERROR_KINDS.contains(&k) => allowed_errors += 1,
                    _ => {
                        unexpected_errors += 1;
                        if unexpected_samples.len() < 8 {
                            unexpected_samples.push(format!("{err:?}"));
                        }
                    }
                }
            }
        }
    }

    let duration_ms = start.elapsed().as_millis().max(1);
    let passed = observed_panics == 0
        && invariant_violations == 0
        && successful_scans >= MIN_SUCCESSFUL_SCANS
        && unexpected_errors == 0;
    // The record carries exactly the compared values: its verdict equals `passed`. The floor
    // is an inequality, so the compared value is whether the floor was met.
    let record = caplog_support::Record::new("mutation_gauntlet_10k")
        .check("panics", 0_usize, observed_panics)
        .check("invariant_violations", 0_usize, invariant_violations)
        .check(
            "successful_scans_at_least_8000",
            true,
            successful_scans >= MIN_SUCCESSFUL_SCANS,
        )
        .check("unexpected_errors", 0_usize, unexpected_errors);
    record.emit(duration_ms);
    let observed = format!(
        "{} successful_scans={successful_scans} allowed_errors={allowed_errors} \
         iterations={iterations} unexpected_samples={unexpected_samples:?}",
        record.observed_json()
    );

    assert!(passed, "10k gauntlet: observed {observed}");
    assert_eq!(observed_panics, 0);
    assert_eq!(invariant_violations, 0);
    assert!(
        successful_scans >= MIN_SUCCESSFUL_SCANS,
        "successful scans {successful_scans} below floor {MIN_SUCCESSFUL_SCANS}"
    );
    assert_eq!(
        unexpected_errors, 0,
        "unexpected error kinds (allowed: {ALLOWED_ERROR_KINDS:?}): {unexpected_samples:?}"
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

    let scan1_res = split_jpeg_stream(&s1, &limits, None);

    // 16.2 Cut after high length byte
    let mut s2 = helper_frame(8, 8, &[0x11]); // 28 bytes
    s2.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00]); // 5 bytes: length 0x00FF overflows
    s2.extend(helper_frame(8, 8, &[0x22])); // 28 bytes

    let scan2_res = split_jpeg_stream(&s2, &limits, None);

    let duration_ms = start.elapsed().as_millis().max(1);
    let expected: Vec<(&str, Outcome)> = vec![
        (
            "cut_after_marker_code",
            Ok(ScanView {
                frames: vec![
                    complete(0, 0, 28, 2, Some((8, 8))),
                    // The next SOI (FF D8 at 32..34) is read as APP0's declared length 0xFFD8.
                    truncated(1, 28, 32, 1, None),
                    complete(2, 32, 60, 2, Some((8, 8))),
                ],
                omissions: Vec::new(),
                findings: vec![
                    JpegFinding::MarkerLengthOverflow {
                        frame_index: 1,
                        offset: 30,
                        marker: 0xE0,
                        length: 0xFFD8,
                        available: 28,
                    },
                    JpegFinding::TruncatedFrame {
                        frame_index: 1,
                        start_offset: 28,
                        end_offset: 32,
                    },
                ],
            }),
        ),
        (
            "cut_after_high_length_byte",
            Ok(ScanView {
                frames: vec![
                    complete(0, 0, 28, 2, Some((8, 8))),
                    // Declared length 0x00FF: high byte 00, low byte is the next SOI's FF.
                    truncated(1, 28, 33, 1, None),
                    complete(2, 33, 61, 2, Some((8, 8))),
                ],
                omissions: Vec::new(),
                findings: vec![
                    JpegFinding::MarkerLengthOverflow {
                        frame_index: 1,
                        offset: 30,
                        marker: 0xE0,
                        length: 0x00FF,
                        available: 29,
                    },
                    JpegFinding::TruncatedFrame {
                        frame_index: 1,
                        start_offset: 28,
                        end_offset: 33,
                    },
                ],
            }),
        ),
    ];
    let observed: Vec<(&str, Outcome)> = vec![
        ("cut_after_marker_code", observe(&scan1_res)),
        ("cut_after_high_length_byte", observe(&scan2_res)),
    ];
    let passed = observed == expected;
    emit_verdict(
        "gauntlet_cut_headers",
        passed,
        &named_outcomes_json(&expected),
        &named_outcomes_json(&observed),
        duration_ms,
    );
    assert!(
        passed,
        "cut headers: expected {expected:?}, observed {observed:?}"
    );
    assert_eq!(observed, expected);

    let scan1 = scan1_res?;
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

    let scan2 = scan2_res?;
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

    let scan_res = split_jpeg_stream(&f, &limits, None);
    let duration_ms = start.elapsed().as_millis().max(1);

    let expected: Outcome = Ok(ScanView {
        frames: vec![
            truncated(0, 0, 27, 2, Some((8, 8))),
            complete(1, 27, 55, 2, Some((8, 8))),
        ],
        omissions: Vec::new(),
        findings: vec![JpegFinding::TruncatedFrame {
            frame_index: 0,
            start_offset: 0,
            end_offset: 27,
        }],
    });
    let observed = observe(&scan_res);
    let passed = observed == expected;
    emit_verdict(
        "gauntlet_nested_soi",
        passed,
        &outcome_json(&expected),
        &outcome_json(&observed),
        duration_ms,
    );
    assert!(
        passed,
        "nested SOI: expected {expected:?}, observed {observed:?}"
    );
    assert_eq!(observed, expected);
    let scan = scan_res?;
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

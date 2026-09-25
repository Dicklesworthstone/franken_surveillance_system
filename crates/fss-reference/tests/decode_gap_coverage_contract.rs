#![forbid(unsafe_code)]
//! Decode refusals as typed coverage gaps (fss-fnrgr follow-up).
//!
//! With `WatchOptions::tolerate_decode_refusals`:
//! 1. a corrupt MJPEG frame mid-recording is one `decode_refused` interval naming its error id,
//!    tracking restarts after it (no candidate's observations straddle the gap), and no witness
//!    claims the gap; without the option the analysis refuses exactly as before;
//! 2. an H.264 stream with a corrupted P slice resumes at the next IDR, and every segment from
//!    the refusal to that IDR is refused and uncovered;
//! 3. a tolerant run that meets no refusal is byte-identical to the default analysis;
//! 4. records round-trip canonically and analyses are deterministic.

#[path = "cascade_support/mod.rs"]
mod support;

use fss_core::{CaptureInterval, ContentDigest};
use fss_reference::ingest::FileFormatHint;
use fss_reference::ingest::recorded_coverage::{CoverageRecord, UncoveredReason};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchLimits, WatchOptions, WatchPlan, WatchReport, WatchTrackerConfig,
    WatchZone,
};
use fss_reference::ingest::tolerant_decode::DecodeRefusal;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use support::{Fixture, TestResult};

const H264: &[u8] =
    include_bytes!("../../fss-codec-h264/tests/fixtures/decode/p_qcif_ref3_p4x4.h264");
const TOLERANT: WatchOptions = WatchOptions {
    tolerate_decode_refusals: true,
};

/// 96x48 grayscale MJPEG: a bright 16x16 square enters from the left at frame 3 and moves 8 px
/// per frame. With `corrupt`, that frame's SOF0 names quantization table 4 (malformed).
fn square_scene(corrupt: Option<usize>) -> TestResult<Vec<u8>> {
    let (width, height) = (96_u32, 48_u32);
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..14_usize {
        let mut pixels = vec![40_u8; (width * height) as usize];
        if index >= 3 {
            let left = (index - 3) * 8;
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * width as usize + x] = 220;
                }
            }
        }
        let mut frame = encode_jpeg(width, height, &pixels, &config)?;
        if corrupt == Some(index) {
            let sof = frame
                .windows(2)
                .position(|pair| pair == [0xFF, 0xC0])
                .ok_or("no SOF0 marker")?;
            frame[sof + 12] = 4;
        }
        stream.extend(frame);
    }
    Ok(stream)
}

/// Two copies of the 12-picture `p_qcif_ref3_p4x4` stream (IDR at segments 0 and 12), with the
/// P slice of segment 3 truncated to 20 bytes.
fn corrupted_h264() -> TestResult<Vec<u8>> {
    let mut starts = Vec::new();
    let mut from = 0;
    while let Some(offset) = H264[from..].windows(3).position(|w| w == [0, 0, 1]) {
        starts.push(from + offset + 3);
        from += offset + 3;
    }
    // NAL units: SPS, PPS, SEI, IDR, then eleven P slices; segment 3 is the seventh NAL unit.
    let slice = *starts.get(6).ok_or("fixture NAL layout")?;
    let next = *starts.get(7).ok_or("fixture NAL layout")?;
    if H264[slice] & 0x1f != 1 {
        return Err("expected a non-IDR slice".into());
    }
    let resume = if H264[next - 4] == 0 {
        next - 4
    } else {
        next - 3
    };
    let mut first = H264[..slice + 20].to_vec();
    first.extend_from_slice(&H264[resume..]);
    let mut stream = first;
    stream.extend_from_slice(H264);
    Ok(stream)
}

fn plan(
    import: ContentDigest,
    interpretation: ComponentInterpretation,
    zone: WatchZone,
    count: usize,
) -> WatchPlan {
    WatchPlan {
        import_identity: import,
        interpretation,
        first_segment: 0,
        segment_count: count,
        zones: vec![zone],
        detector: WatchDetectorConfig::default(),
        tracker: WatchTrackerConfig::default(),
    }
}

fn door() -> WatchZone {
    WatchZone {
        zone_id: "door".to_owned(),
        x: 64,
        y: 0,
        width: 32,
        height: 32,
    }
}

fn uncovered(record: &CoverageRecord) -> Vec<(String, u64, u64)> {
    record.zones[0]
        .uncovered
        .iter()
        .map(|gap| {
            let reason = match &gap.reason {
                UncoveredReason::DecodeRefused { error_id } => format!("decode_refused:{error_id}"),
                other => other.as_str().to_owned(),
            };
            (reason, gap.first_segment, gap.last_segment)
        })
        .collect()
}

/// Every `decode_refused` interval is one of `refused`, and no witness spans one: witnesses end
/// before it or start after it, so their certain bounds (latest capture of the first frame to
/// earliest capture of the last) never reach into the refused segments.
fn assert_no_witness_over(record: &CoverageRecord, refused: &[(u64, u64)]) {
    for zone in &record.zones {
        for gap in &zone.uncovered {
            if !matches!(gap.reason, UncoveredReason::DecodeRefused { .. }) {
                continue;
            }
            assert!(refused.contains(&(gap.first_segment, gap.last_segment)));
            for witness in &zone.witnesses {
                assert!(
                    witness.last_segment < gap.first_segment
                        || witness.first_segment > gap.last_segment,
                    "a witness spans refused segments {}..{}",
                    gap.first_segment,
                    gap.last_segment
                );
            }
        }
    }
}

fn before(a: CaptureInterval, b: CaptureInterval) -> bool {
    a.latest < b.earliest
}

#[test]
fn a_corrupt_mjpeg_frame_is_one_refused_interval_and_tracks_never_bridge_it() -> TestResult {
    let mut fixture = Fixture::new("gap-mjpeg")?;
    let import = fixture.ingest(
        "sensor:gap-mjpeg",
        &square_scene(Some(6))?,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    let plan = plan(import, ComponentInterpretation::Grayscale, door(), 14);
    let limits = WatchLimits::default();

    // Default: today's refusal, nothing analysed.
    let refused = WatchReport::analyze(&fixture.deployment, &plan, &limits, &fixture.cx)
        .err()
        .ok_or("the default analysis must refuse the corrupt frame")?;
    assert_eq!(refused.stable_id(), "ERR-DECODE-001");

    let report = WatchReport::analyze_with_options(
        &fixture.deployment,
        &plan,
        &limits,
        None,
        TOLERANT,
        &fixture.cx,
    )?;
    assert_eq!(
        report.decode_refusals(),
        &[DecodeRefusal {
            first_segment: 6,
            last_segment: 6,
            error_id: "ERR-DECODE-001".to_owned(),
        }]
    );
    let decoded: Vec<usize> = report.frames().iter().map(|f| f.segment).collect();
    assert_eq!(decoded, [0, 1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13]);
    // Tracking restarted after the gap: every candidate's matched frames lie on one side.
    assert!(!report.candidates().is_empty());
    for candidate in report.candidates() {
        let [first, last] = candidate.frame_range();
        assert!(
            last < 6 || first > 6,
            "track bridged the gap: {first}..{last}"
        );
        assert!(candidate.entry_segment > 6);
    }
    let record = report.coverage();
    let gaps = uncovered(record);
    assert_eq!(
        gaps.iter()
            .filter(|(reason, _, _)| reason.starts_with("decode_refused"))
            .collect::<Vec<_>>(),
        vec![&("decode_refused:ERR-DECODE-001".to_owned(), 6, 6)]
    );
    // The frames before the gap cannot confirm a new track before tracking restarts.
    assert!(
        gaps.contains(&("confirmation_latency".to_owned(), 4, 5)),
        "{gaps:?}"
    );
    assert_no_witness_over(record, &[(6, 6)]);
    assert_eq!(
        CoverageRecord::from_bytes(&record.to_bytes(), record.digest())?,
        record.clone()
    );
    let json = report.to_json(0, Some("fss-event watch --tolerate-decode-refusals"));
    assert!(
        json.contains(
            ",\"decode_refusals\":[{\"first_segment\":6,\"last_segment\":6,\"error_id\":\"ERR-DECODE-001\",\"coverage\":\"decode_refused\"}]"
        ),
        "{json}"
    );

    // Deterministic.
    let again = WatchReport::analyze_with_options(
        &fixture.deployment,
        &plan,
        &limits,
        None,
        TOLERANT,
        &fixture.cx,
    )?;
    assert_eq!(again.to_json(0, None), report.to_json(0, None));
    assert_eq!(again.coverage().to_bytes(), record.to_bytes());
    Ok(())
}

#[test]
fn a_quiet_scene_split_by_a_refusal_keeps_two_disjoint_witnesses() -> TestResult {
    let mut fixture = Fixture::new("gap-quiet")?;
    // A static scene whose frame 9 is corrupt.
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..14_usize {
        let mut frame = encode_jpeg(96, 48, &vec![40_u8; 96 * 48], &config)?;
        if index == 9 {
            let sof = frame
                .windows(2)
                .position(|pair| pair == [0xFF, 0xC0])
                .ok_or("no SOF0 marker")?;
            frame[sof + 12] = 4;
        }
        stream.extend(frame);
    }
    let import = fixture.ingest(
        "sensor:gap-quiet",
        &stream,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    let report = WatchReport::analyze_with_options(
        &fixture.deployment,
        &plan(import, ComponentInterpretation::Grayscale, door(), 14),
        &WatchLimits::default(),
        None,
        TOLERANT,
        &fixture.cx,
    )?;
    let record = report.coverage();
    let witnesses: Vec<(u64, u64)> = record.zones[0]
        .witnesses
        .iter()
        .map(|w| (w.first_segment, w.last_segment))
        .collect();
    // Warm-up 0..3; latency before the restart 7..8; refused 9; latency at the end 12..13.
    assert_eq!(witnesses, [(4, 6), (10, 11)]);
    assert_eq!(
        uncovered(record),
        vec![
            ("background_warmup".to_owned(), 0, 3),
            ("confirmation_latency".to_owned(), 7, 8),
            ("decode_refused:ERR-DECODE-001".to_owned(), 9, 9),
            ("confirmation_latency".to_owned(), 12, 13),
        ]
    );
    assert_no_witness_over(record, &[(9, 9)]);
    let (first, second) = (&record.zones[0].witnesses[0], &record.zones[0].witnesses[1]);
    assert!(before(first.covered, second.covered));
    Ok(())
}

#[test]
fn an_h264_stream_with_a_corrupted_p_slice_resumes_at_the_next_idr() -> TestResult {
    let mut fixture = Fixture::new("gap-h264")?;
    let import = fixture.ingest(
        "sensor:gap-h264",
        &corrupted_h264()?,
        FileFormatHint::AnnexB,
        Some(1_000_000_000),
    )?;
    let scene = WatchZone {
        zone_id: "scene".to_owned(),
        x: 0,
        y: 0,
        width: 176,
        height: 144,
    };
    let plan = plan(import, ComponentInterpretation::YCbCr, scene, 24);
    let limits = WatchLimits::default();
    let refused = WatchReport::analyze(&fixture.deployment, &plan, &limits, &fixture.cx)
        .err()
        .ok_or("the default analysis must refuse the corrupted slice")?;
    assert_eq!(refused.stable_id(), "ERR-DECODE-BOUNDS-001", "{refused}");

    let report = WatchReport::analyze_with_options(
        &fixture.deployment,
        &plan,
        &limits,
        None,
        TOLERANT,
        &fixture.cx,
    )?;
    // Every segment from the corrupted slice to the IDR of the second copy is refused. The codec
    // reports the slice's exhausted bitstream as its `Limit` (ERR-DECODE-BOUNDS-001).
    let refusals = report.decode_refusals();
    assert_eq!(
        refusals,
        &[DecodeRefusal {
            first_segment: 3,
            last_segment: 11,
            error_id: "ERR-DECODE-BOUNDS-001".to_owned(),
        }]
    );
    let refusal = &refusals[0];
    let decoded: Vec<usize> = report.frames().iter().map(|f| f.segment).collect();
    let after: Vec<usize> = (12..24).collect();
    assert_eq!(decoded, [vec![0, 1, 2], after].concat());
    let record = report.coverage();
    assert!(uncovered(record).contains(&(
        format!("decode_refused:{}", refusal.error_id),
        refusal.first_segment as u64,
        11
    )));
    assert_no_witness_over(record, &[(refusal.first_segment as u64, 11)]);
    // The second copy is analysed normally after the restart: it carries a witness.
    assert!(
        record.zones[0]
            .witnesses
            .iter()
            .any(|w| w.first_segment >= 12)
    );
    assert_eq!(
        CoverageRecord::from_bytes(&record.to_bytes(), record.digest())?,
        record.clone()
    );
    let again = WatchReport::analyze_with_options(
        &fixture.deployment,
        &plan,
        &limits,
        None,
        TOLERANT,
        &fixture.cx,
    )?;
    assert_eq!(again.coverage().to_bytes(), record.to_bytes());
    assert_eq!(again.to_json(0, None), report.to_json(0, None));
    Ok(())
}

#[test]
fn a_tolerant_run_without_refusals_is_byte_identical_to_the_default() -> TestResult {
    let mut fixture = Fixture::new("gap-clean")?;
    let mjpeg = fixture.ingest(
        "sensor:gap-clean-mjpeg",
        &square_scene(None)?,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    let h264 = fixture.ingest(
        "sensor:gap-clean-h264",
        H264,
        FileFormatHint::AnnexB,
        Some(1_000_000_000),
    )?;
    let scene = WatchZone {
        zone_id: "scene".to_owned(),
        x: 0,
        y: 0,
        width: 176,
        height: 144,
    };
    for plan in [
        plan(mjpeg, ComponentInterpretation::Grayscale, door(), 14),
        plan(h264, ComponentInterpretation::YCbCr, scene, 12),
    ] {
        let limits = WatchLimits::default();
        let strict = WatchReport::analyze(&fixture.deployment, &plan, &limits, &fixture.cx)?;
        let tolerant = WatchReport::analyze_with_options(
            &fixture.deployment,
            &plan,
            &limits,
            None,
            TOLERANT,
            &fixture.cx,
        )?;
        assert!(tolerant.decode_refusals().is_empty());
        assert_eq!(
            tolerant.to_json(3, Some("hint")),
            strict.to_json(3, Some("hint"))
        );
        assert_eq!(tolerant.coverage().to_bytes(), strict.coverage().to_bytes());
        assert_eq!(tolerant.coverage_approval(), strict.coverage_approval());
    }
    Ok(())
}

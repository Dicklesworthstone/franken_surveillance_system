#![forbid(unsafe_code)]
//! Byte-for-byte pins of the model-free watch and corroborate reports (fss-704tz).
//!
//! The pinned SHA-256 values were produced by this exact file against the pre-cascade tree
//! (commit 2c0cc07, before the detector cascade and chroma decode existed); the test uses only
//! APIs that existed there. It must keep passing unchanged: without `--detector-package` the
//! watch and corroborate outputs may not change by a single byte.

#[path = "cascade_support/mod.rs"]
mod support;

use fss_core::ContentDigest;
use fss_reference::ingest::FileFormatHint;
use fss_reference::ingest::recorded_corroboration::{
    CorroborationCamera, CorroborationGates, CorroborationPlan, CorroborationReport,
    GroundHomography, GroundZone,
};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchLimits, WatchPlan, WatchReport, WatchTrackerConfig, WatchZone,
};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use support::{Fixture, TestResult};

const H264: &[u8] =
    include_bytes!("../../fss-codec-h264/tests/fixtures/decode/p_qcif_ref3_p4x4.h264");
const HEVC: &[u8] = include_bytes!("fixtures/hevc_ingest/watch_96x48_moving.h265");

/// Direction of the moving bright square.
#[derive(Clone, Copy)]
enum Motion {
    Right,
    Left,
}

/// 96x48 grayscale MJPEG: dark background; from frame 3 a bright 16x16 square moves 8 px per
/// frame along the top band (the scene of the watch and corroborate CLI contracts).
fn square_scene(motion: Motion) -> TestResult<Vec<u8>> {
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
            let left = match motion {
                Motion::Right => (index - 3) * 8,
                Motion::Left => 80 - (index - 3) * 8,
            };
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * width as usize + x] = 220;
                }
            }
        }
        stream.extend(encode_jpeg(width, height, &pixels, &config)?);
    }
    Ok(stream)
}

fn zone(id: &str, geometry: [u32; 4]) -> WatchZone {
    WatchZone {
        zone_id: id.to_owned(),
        x: geometry[0],
        y: geometry[1],
        width: geometry[2],
        height: geometry[3],
    }
}

fn watch_json(
    fixture: &Fixture,
    import: ContentDigest,
    interpretation: ComponentInterpretation,
    count: usize,
    zones: Vec<WatchZone>,
) -> TestResult<String> {
    let plan = WatchPlan {
        import_identity: import,
        interpretation,
        first_segment: 0,
        segment_count: count,
        zones,
        detector: WatchDetectorConfig::default(),
        tracker: WatchTrackerConfig::default(),
    };
    let report = WatchReport::analyze(
        &fixture.deployment,
        &plan,
        &WatchLimits::default(),
        &fixture.cx,
    )?;
    Ok(report.to_json(0, Some("fss-event watch --golden")))
}

fn digest(text: &str) -> String {
    ContentDigest::sha256(text.as_bytes()).to_text()
}

#[test]
fn model_free_watch_reports_are_byte_identical_to_the_pre_cascade_tree() -> TestResult {
    let mut fixture = Fixture::new("golden-watch")?;
    let mjpeg = fixture.ingest(
        "sensor:golden-mjpeg",
        &square_scene(Motion::Right)?,
        FileFormatHint::JpegStream,
        None,
    )?;
    let h264 = fixture.ingest("sensor:golden-h264", H264, FileFormatHint::AnnexB, None)?;
    let hevc = fixture.ingest("sensor:golden-hevc", HEVC, FileFormatHint::Hevc, None)?;
    let square = watch_json(
        &fixture,
        mjpeg,
        ComponentInterpretation::Grayscale,
        14,
        vec![zone("door", [64, 0, 32, 32])],
    )?;
    assert!(square.contains("\"candidate_count\":1"), "{square}");
    let avc = watch_json(
        &fixture,
        h264,
        ComponentInterpretation::YCbCr,
        12,
        vec![zone("scene", [0, 0, 176, 144])],
    )?;
    let hevc = watch_json(
        &fixture,
        hevc,
        ComponentInterpretation::YCbCr,
        14,
        vec![zone("door", [64, 0, 32, 32])],
    )?;
    assert!(hevc.contains("\"candidate_count\":1"), "{hevc}");
    let observed = [digest(&square), digest(&avc), digest(&hevc)];
    println!("golden watch digests: {observed:?}");
    assert_eq!(observed, GOLDEN_WATCH);
    Ok(())
}

#[test]
fn model_free_corroboration_report_is_byte_identical_to_the_pre_cascade_tree() -> TestResult {
    let mut fixture = Fixture::new("golden-corroborate")?;
    let east = fixture.ingest(
        "sensor:golden-east",
        &square_scene(Motion::Right)?,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    let west = fixture.ingest(
        "sensor:golden-west",
        &square_scene(Motion::Left)?,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    let plan = CorroborationPlan {
        cameras: [
            CorroborationCamera {
                name: "east".to_owned(),
                import_identity: east,
                homography: GroundHomography {
                    matrix: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
                },
            },
            CorroborationCamera {
                name: "west".to_owned(),
                import_identity: west,
                homography: GroundHomography {
                    matrix: [-1.0, 0.0, 96.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
                },
            },
        ],
        interpretation: ComponentInterpretation::Grayscale,
        zones: vec![GroundZone {
            zone_id: "door".to_owned(),
            x: 56.0,
            y: 0.0,
            width: 40.0,
            height: 48.0,
        }],
        gates: CorroborationGates {
            time_gate_ns: 250_000_000,
            distance_gate: 16.0,
        },
        detector: WatchDetectorConfig::default(),
        tracker: WatchTrackerConfig::default(),
    };
    let report = CorroborationReport::analyze(
        &fixture.deployment,
        &plan,
        &WatchLimits::default(),
        &fixture.cx,
    )?;
    let json = report.to_json(
        0,
        Some("fss-event corroborate --golden"),
        Some("fss-event alert"),
    );
    assert!(json.contains("\"candidate_count\":1"), "{json}");
    let observed = digest(&json);
    println!("golden corroboration digest: {observed}");
    assert_eq!(observed, GOLDEN_CORROBORATION);
    Ok(())
}

/// Square MJPEG, H.264 `p_qcif_ref3_p4x4`, H.265 `watch_96x48_moving` (produced at 2c0cc07).
const GOLDEN_WATCH: [&str; 3] = [
    "sha256:841b6ccf7d2a90a200ade290877a6a282599c73e8bf2c3a446ae145122841160",
    "sha256:97bbdd76ff765d83262827b40b5bd537bfe66a3b26ccae4f1a16bc287484a0d0",
    "sha256:4b82b295d60cef9df2ac5bdeff8fb0900b29146e23fc8aa60f56e736ecd40bb4",
];
/// Two mirrored square MJPEG recordings (produced at 2c0cc07).
const GOLDEN_CORROBORATION: &str =
    "sha256:9f51121c0eef5e0fea42be489bbbec58b882c42368544745b253ffb14710353a";

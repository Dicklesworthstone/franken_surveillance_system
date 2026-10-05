#![forbid(unsafe_code)]
//! Byte-for-byte pins of model-free watch coverage records over image zones (fss-2h5zq.53).
//!
//! Geometric visibility and tolerant decoding are opt-in extensions of the coverage record. An
//! image-zone watch without either must keep producing the exact record bytes it produced
//! before they existed. The pinned SHA-256 values were produced by this exact file against
//! commit a4d0255 (before ground visibility and decode-gap coverage); the test uses only APIs
//! that existed there, so it must keep passing unchanged.

#[path = "cascade_support/mod.rs"]
mod support;

use fss_core::ContentDigest;
use fss_reference::ingest::FileFormatHint;
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchLimits, WatchPlan, WatchReport, WatchTrackerConfig, WatchZone,
};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use support::{Fixture, TestResult};

const H264: &[u8] =
    include_bytes!("../../fss-codec-h264/tests/fixtures/decode/p_qcif_ref3_p4x4.h264");
const HEVC: &[u8] = include_bytes!("fixtures/hevc_ingest/watch_96x48_moving.h265");

/// 96x48 grayscale MJPEG; from frame 3 a bright 16x16 square moves right 8 px per frame.
fn square_scene() -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..14_usize {
        let mut pixels = vec![40_u8; 96 * 48];
        if index >= 3 {
            let left = (index - 3) * 8;
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * 96 + x] = 220;
                }
            }
        }
        stream.extend(encode_jpeg(96, 48, &pixels, &config)?);
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

/// Record digest and approval digest of one analysis.
fn coverage(
    fixture: &Fixture,
    import: ContentDigest,
    interpretation: ComponentInterpretation,
    count: usize,
    zones: Vec<WatchZone>,
) -> TestResult<[String; 2]> {
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
    Ok([
        report.coverage().digest().to_text(),
        report.coverage_approval().to_text(),
    ])
}

#[test]
fn image_zone_watch_coverage_records_are_byte_identical_to_the_pre_visibility_tree() -> TestResult {
    let mut fixture = Fixture::new("golden-coverage")?;
    let hinted = fixture.ingest(
        "sensor:golden-coverage-hinted",
        &square_scene()?,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    let unknown = fixture.ingest(
        "sensor:golden-coverage-unknown",
        &square_scene()?,
        FileFormatHint::JpegStream,
        None,
    )?;
    let h264 = fixture.ingest(
        "sensor:golden-coverage-h264",
        H264,
        FileFormatHint::AnnexB,
        Some(1_000_000_000),
    )?;
    let hevc = fixture.ingest(
        "sensor:golden-coverage-hevc",
        HEVC,
        FileFormatHint::Hevc,
        Some(1_000_000_000),
    )?;
    let observed = [
        coverage(
            &fixture,
            hinted,
            ComponentInterpretation::Grayscale,
            14,
            vec![zone("door", [64, 0, 32, 32]), zone("wide", [0, 0, 200, 48])],
        )?,
        coverage(
            &fixture,
            unknown,
            ComponentInterpretation::Grayscale,
            14,
            vec![zone("door", [64, 0, 32, 32])],
        )?,
        coverage(
            &fixture,
            h264,
            ComponentInterpretation::YCbCr,
            12,
            vec![zone("scene", [0, 0, 176, 144])],
        )?,
        coverage(
            &fixture,
            hevc,
            ComponentInterpretation::YCbCr,
            14,
            vec![zone("door", [64, 0, 32, 32])],
        )?,
    ];
    println!("golden coverage digests: {observed:?}");
    assert_eq!(observed, GOLDEN_COVERAGE);
    Ok(())
}

/// (record digest, approval digest) of: hinted square MJPEG with an in-frame and an
/// out-of-frame zone, the same scene with unknown capture time, H.264 `p_qcif_ref3_p4x4`, and
/// H.265 `watch_96x48_moving` (produced at a4d0255; re-pinned at b31b988). fss-2h5zq.25 (7751a78) and fss-2h5zq.24
/// (e10dd6e) made acquisition-session records import-root children, and each record binds the
/// import and its basis anchor. These record bytes were NOT diffed directly; the watch report
/// JSON over the same fixtures differs only in import-derived identities (watch_report_golden).
const GOLDEN_COVERAGE: [[&str; 2]; 4] = [
    [
        "sha256:c6cc6a3d724546848ec0c0b633a18b354152f5233e7c334f19257670a2a5aa2d",
        "sha256:4c6f9ff030ef4989a68e3b89314734d2cb3cfe4f3bebf209623be88314db2b7d",
    ],
    [
        "sha256:d0ac7991ac57f0fb9a99d5d7c6ac69fb8e34d9e35d70859248bb04e86c7e9fdc",
        "sha256:8d777272669350982b41d78b0f69727820468c39c4cd6b668ffc6955eab083d6",
    ],
    [
        "sha256:aa4696379987577e41819344560c612b0aaa64d729cab321fbc5c3571439753a",
        "sha256:b210939417f682b1539d1f12912b5fb05bef9913604993185d2fec836833f48a",
    ],
    [
        "sha256:2f25072079c99145684a5da1ffbae0b13c794f346efe8b03efadce8ad9626c99",
        "sha256:7e062ee32efcb872044f0e093d451354aaed3f69fe141424d64392d14759c411",
    ],
];

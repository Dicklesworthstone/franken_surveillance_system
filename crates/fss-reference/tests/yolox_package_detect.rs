#![forbid(unsafe_code)]
//! Retained recordings (MJPEG, H.264, H.265) through the verified YOLOX-Nano package into the
//! package detection report (fss-q4ngj). Proves wiring and source binding; the JPEG frame is
//! also cross-checked against the laboratory-oracle detections. No quality claim.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::package_detect::{
    PackageDetectError, PackageDetectLimits, PackageDetectRequest, run_package_detection,
};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::{FileFormatHint, FileIngestAdapter, FileIngestRequest};
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
/// (`media_format:color`, [(class, source bounds in 1/256 px)]) of the single frame.
type FrameSummary = (String, Vec<(usize, [u32; 4])>);

const PACKAGE_SHA256: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";
const PACKAGE: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");
const FIXTURE: &str = include_str!("fixtures/yolox_nano/conformance.txt");
const JPEG: &[u8] =
    include_bytes!("../../../tests/fixtures/media/jpeg/rgb_64x48_colorbars_420.jpg");
const H264: &[u8] = include_bytes!("../../fss-packet/tests/fixtures/avc/baseline.264");
const H265: &[u8] = include_bytes!("fixtures/hevc_ingest/watch_96x48_moving.h265");

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-yolox-detect-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:yolox-detect".into(),
        operation_id: OperationId::parse("operation:yolox-detect")?,
        principal: "principal:yolox-detect".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .storage_operations(4096)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"site:yolox-detect"),
        generation: 1,
    })?;
    authority.validate()?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

fn detect(
    name: &str,
    file: &str,
    bytes: &[u8],
    hint: Option<FileFormatHint>,
    first: usize,
) -> TestResult<FrameSummary> {
    let directory = OwnedDirectory::new(name)?;
    let root = directory.0.join("deployment");
    let path = directory.0.join(file);
    fs::write(&path, bytes)?;
    let cx = context(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, "site:yolox-detect", &cx)?;
    let mut request = FileIngestRequest::new(
        path,
        SensorId::parse("sensor:yolox-detect")?,
        StreamId::parse("stream:yolox-detect")?,
    )
    .with_receive_time(TimestampNs(1_000_000_000));
    request.format_hint = hint;
    let identity = FileIngestAdapter::ingest(request, &cx, &mut deployment)?.import_identity;
    let scalar = ScalarExecCx::new();
    let package = RgbDetectorPackage::load(
        PACKAGE,
        ContentDigest::parse(PACKAGE_SHA256)?,
        1 << 40,
        &cx,
        &scalar,
    )?;
    let before = deployment.current_anchor().clone();
    let request = PackageDetectRequest {
        import_identity: identity,
        first_segment: first,
        segment_count: 1,
        interpretation: ComponentInterpretation::YCbCr,
        minimum_score_ppm: None,
    };
    let limits = PackageDetectLimits::default();
    // Bounds are refused before any decode or inference.
    for bad in [
        PackageDetectRequest {
            segment_count: 0,
            ..request.clone()
        },
        PackageDetectRequest {
            segment_count: 65,
            ..request.clone()
        },
        PackageDetectRequest {
            first_segment: 1 << 20,
            ..request.clone()
        },
    ] {
        let refused = run_package_detection(&deployment, &package, &bad, &limits, &cx, &scalar);
        assert!(
            matches!(refused, Err(ref e @ PackageDetectError::InvalidRequest) if e.stable_id() == "ERR-PACKAGE-DETECT-REQUEST-001")
        );
    }
    let report = run_package_detection(&deployment, &package, &request, &limits, &cx, &scalar)?;
    // Read-only: no authority change.
    assert_eq!(*deployment.current_anchor(), before);
    assert_eq!(report.frames.len(), 1);
    assert_eq!(report.digest, ContentDigest::sha256(report.json.as_bytes()));
    for needle in [
        "\"schema\":\"fss.package_detection_report.v1\"",
        "\"model_id\":\"MOD-YOLOXNANO-001\"",
        "\"model_outputs\":\"uncalibrated\"",
        "\"absence_certifiable\":false",
        "\"effects_authorized\":false",
        "\"quality_claim\":\"none\"",
        &format!("\"package_digest\":\"{PACKAGE_SHA256}\""),
    ] {
        assert!(
            report.json.contains(needle),
            "{needle} missing from {}",
            report.json
        );
    }
    let frame = &report.frames[0];
    let detections = frame
        .detections
        .detections()
        .iter()
        .map(|d| (d.class_index(), d.bounds()))
        .collect();
    Ok((
        format!("{}:{}", report.media_format, frame.color),
        detections,
    ))
}

#[test]
fn retained_jpeg_frames_reproduce_the_oracle_detections() -> TestResult {
    let (kind, detections) = detect("mjpeg", "camera.mjpeg", JPEG, None, 0)?;
    assert_eq!(kind, "mjpeg:jpeg_rgb");
    let mut in_case = false;
    let mut expected = Vec::new();
    for line in FIXTURE.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        match f.as_slice() {
            ["case", name] => in_case = *name == "jpeg_colorbars",
            ["det", "300000", _row, class, _score, b @ ..] if in_case => {
                expected.push((
                    class.parse::<usize>()?,
                    [
                        b[0].parse::<u32>()?,
                        b[1].parse()?,
                        b[2].parse()?,
                        b[3].parse()?,
                    ],
                ));
            }
            _ => {}
        }
    }
    assert!(!expected.is_empty());
    assert_eq!(detections.len(), expected.len());
    for (class, bounds) in expected {
        assert!(
            detections.iter().any(
                |(c, b)| *c == class && b.iter().zip(bounds).all(|(x, y)| x.abs_diff(y) <= 128)
            ),
            "oracle detection {class} {bounds:?} not reproduced from retained custody"
        );
    }
    Ok(())
}

#[test]
fn retained_h264_and_h265_frames_run_as_explicit_grayscale() -> TestResult {
    let (kind, _) = detect("h264", "camera.h264", H264, Some(FileFormatHint::AnnexB), 0)?;
    assert_eq!(kind, "annexb:luma_replicated");
    let (kind, _) = detect("h265", "camera.h265", H265, Some(FileFormatHint::Hevc), 0)?;
    assert_eq!(kind, "hevc:luma_replicated");
    Ok(())
}

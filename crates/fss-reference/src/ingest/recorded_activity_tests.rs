#![forbid(unsafe_code)]

use super::*;
use crate::executor_activity::{ActivityThresholdPolicy, ExecutorModelOutcome};
use crate::executor_activity_package::ACTIVITY_PACKAGE_V1_SHA256;
use crate::ingest::{FileFormatHint, FileIngestAdapter, FileIngestRequest};
use crate::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use crate::{ADP_FILE_ROW_ID, ADP_REPLAY_ROW_ID, ExecBudget, ReplayIoAuthority};
use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::{
    BudgetVector, ContextAuthority, OperationId, RootAuthoritySpec, SensorId, StreamId, TimestampNs,
};
use std::error::Error as StdError;
use std::fs;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = std::result::Result<T, Box<dyn StdError>>;

const H264: &[u8] =
    include_bytes!("../../../fss-codec-h264/tests/fixtures/decode/p_qcif_ref3_p4x4.h264");
const H265: &[u8] = include_bytes!("../../tests/fixtures/hevc_ingest/watch_96x48_moving.h265");
const H265_MP4: &[u8] = include_bytes!("../../tests/fixtures/hevc_ingest/watch_96x48_moving.mp4");

struct TempDir(PathBuf);
impl TempDir {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-rec-act-unit-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("temp dir capacity".into())
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:recorded-activity-unit".to_owned(),
        operation_id: OperationId::parse("operation:recorded-activity-unit")?,
        principal: "operator:recorded-activity-unit".to_owned(),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_owned(), ADP_FILE_ROW_ID.to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_owned(),
        retention_scope: "retention:ephemeral".to_owned(),
        anchor_universe: ContentDigest::sha256(b"recorded-activity-unit"),
        generation: 1,
    })?;
    Ok(ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority,
        root.join("scratch"),
    )?))
}

fn run_video_case(
    name: &str,
    bytes: &[u8],
    hint: FileFormatHint,
    expected_format: &str,
    reference_segment: usize,
    segment: usize,
) -> TestResult {
    let dir = TempDir::new(name)?;
    let root = dir.0.join("deployment");
    let input = dir.0.join("input.bin");
    fs::write(&input, bytes)?;
    let cx = context(&dir.0)?;
    let mut deployment = ReferenceDeployment::open(&root, "site:recorded-activity-unit", &cx)?;
    let sensor = SensorId::parse("sensor:recorded-activity-unit")?;
    let stream = StreamId::parse("stream:recorded-activity-unit")?;
    let imported = FileIngestAdapter::ingest(
        FileIngestRequest::new(&input, sensor.clone(), stream.clone())
            .with_format_hint(hint)
            .with_receive_time(TimestampNs(5_000_000_000)),
        &cx,
        &mut deployment,
    )?;
    fs::remove_file(&input)?;
    let request = RecordedActivityRequest {
        import_identity: imported.import_identity,
        reference_segment,
        segment,
        expected_package_sha256: ContentDigest::parse(ACTIVITY_PACKAGE_V1_SHA256)?,
        plan: ActivityReplayPlan {
            sensor_id: sensor,
            stream_id: stream,
            job_id: format!("job:{name}"),
            policy: ActivityThresholdPolicy::reference()?,
            interpretation: ComponentInterpretation::YCbCr,
            execution: ExecBudget::new(10_000_000, 16 * 1024 * 1024),
        },
    };
    // Grayscale contradicts H.264/H.265 4:2:0 and is refused before writes.
    let mut gray_req = request.clone();
    gray_req.plan.interpretation = ComponentInterpretation::Grayscale;
    assert!(
        produce_recorded_activity(
            &mut deployment,
            gray_req,
            RecordedActivityLimits::default(),
            &cx,
            &ScalarExecCx::new(),
        )
        .is_err()
    );

    // Zero decode work allowance still fails closed.
    let tiny_limits = RecordedActivityLimits {
        max_decode_work: 0,
        ..RecordedActivityLimits::default()
    };
    assert!(
        produce_recorded_activity(
            &mut deployment,
            request.clone(),
            tiny_limits,
            &cx,
            &ScalarExecCx::new(),
        )
        .is_err()
    );

    let first = produce_recorded_activity(
        &mut deployment,
        request.clone(),
        RecordedActivityLimits::default(),
        &cx,
        &ScalarExecCx::new(),
    )?;
    assert_eq!(first.media_format, expected_format);
    assert!(first.decode_work > 0);
    assert!(first.source_read_bytes > 0);
    assert!(matches!(
        first.retained.result.outcome,
        ExecutorModelOutcome::Activity { .. } | ExecutorModelOutcome::NoActivity { .. }
    ));
    assert!(!first.retained.result.supports_absence_claim());

    // Exact retry is deterministic and idempotent.
    let second = produce_recorded_activity(
        &mut deployment,
        request,
        RecordedActivityLimits::default(),
        &cx,
        &ScalarExecCx::new(),
    )?;
    assert_eq!(first.retained.result_digest, second.retained.result_digest);
    assert_eq!(first.source_root, second.source_root);
    assert_eq!(first.final_anchor, second.final_anchor);
    assert_eq!(first.decode_work, second.decode_work);
    Ok(())
}

#[test]
fn h264_annexb_activity_succeeds_and_replays_idempotently() -> TestResult {
    run_video_case("h264-idr", H264, FileFormatHint::AnnexB, "annexb", 0, 5)?;
    // Non-zero P-frame reference segment walks back to IDR at segment 0.
    run_video_case("h264-p", H264, FileFormatHint::AnnexB, "annexb", 2, 7)
}

#[test]
fn h265_annexb_and_mp4hevc_activity_succeed_deterministically() -> TestResult {
    run_video_case("h265-raw", H265, FileFormatHint::Hevc, "hevc", 0, 10)?;
    run_video_case("h265-p", H265, FileFormatHint::Hevc, "hevc", 3, 11)?;
    run_video_case(
        "h265-mp4",
        H265_MP4,
        FileFormatHint::Mp4Hevc,
        "mp4hevc",
        0,
        10,
    )
}

#[test]
fn default_limits_cover_640x360_mjpeg_without_budget_exhaustion() -> TestResult {
    let limits = RecordedActivityLimits::default();
    assert!(limits.max_decode_work >= limits.decode.baseline_rgb_work_bound().saturating_mul(2));
    // Must remain compatible with fss-evidence verify-activity's 1B ceiling.
    assert!(limits.max_decode_work <= 1_000_000_000);
    let dir = TempDir::new("mjpeg-640x360")?;
    let root = dir.0.join("deployment");
    let input = dir.0.join("clip.mjpeg");
    let cfg = JpegConfig {
        quality: 85,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let a = encode_jpeg(640, 360, &vec![40_u8; 640 * 360], &cfg)?;
    let b = encode_jpeg(640, 360, &vec![210_u8; 640 * 360], &cfg)?;
    let mut combined = a;
    combined.extend_from_slice(&b);
    fs::write(&input, combined)?;
    let cx = context(&dir.0)?;
    let mut deployment = ReferenceDeployment::open(&root, "site:recorded-activity-unit", &cx)?;
    let sensor = SensorId::parse("sensor:mjpeg-640")?;
    let stream = StreamId::parse("stream:mjpeg-640")?;
    let imported = FileIngestAdapter::ingest(
        FileIngestRequest::new(&input, sensor.clone(), stream.clone())
            .with_receive_time(TimestampNs(5_000_000_000)),
        &cx,
        &mut deployment,
    )?;
    let receipt = produce_recorded_activity(
        &mut deployment,
        RecordedActivityRequest {
            import_identity: imported.import_identity,
            reference_segment: 0,
            segment: 1,
            expected_package_sha256: ContentDigest::parse(ACTIVITY_PACKAGE_V1_SHA256)?,
            plan: ActivityReplayPlan {
                sensor_id: sensor,
                stream_id: stream,
                job_id: "job:mjpeg-640".to_owned(),
                policy: ActivityThresholdPolicy::reference()?,
                interpretation: ComponentInterpretation::Grayscale,
                execution: ExecBudget::new(10_000_000, 16 * 1024 * 1024),
            },
        },
        limits,
        &cx,
        &ScalarExecCx::new(),
    )?;
    assert_eq!(receipt.media_format, "mjpeg");
    assert!(matches!(
        receipt.retained.result.outcome,
        ExecutorModelOutcome::Activity { .. }
    ));
    // Previously hardcoded 20_000_000 would have exhausted on two 640x360 frames (>40M).
    assert!(receipt.decode_work > 20_000_000);
    assert!(receipt.decode_work <= limits.max_decode_work);
    Ok(())
}

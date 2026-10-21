#![forbid(unsafe_code)]
//! Whole-recording native sampling, nonrenewable work and cold source/model custody.
//! Synthetic scenes and the real pinned package exercise mechanics, not detection accuracy.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, ContentDigest, EventKind, EventState, LedgerAnchor, OperationId, SensorId,
    StreamId, TimestampNs,
};
use fss_reference::ingest::long_sentinel::retained::{
    LongSentinelReplayLimits, LongSentinelRetentionError, RetainedLongSentinel,
    rerun_long_sentinel_detection, retain_long_sentinel_detection,
};
use fss_reference::ingest::long_sentinel::{
    LongSentinelConfig, LongSentinelLimits, LongSentinelPlan, LongSentinelRequest,
    run_long_sentinel_detection,
};
use fss_reference::ingest::long_watch::MAX_LONG_WATCH_FRAMES;
use fss_reference::ingest::package_detect::{
    PackageDetectError, PackageDetectRequest, run_package_detection,
};
use fss_reference::ingest::package_event::{
    PackageAnalysisReport, PackageEvent, PackageEventProposal, PackageTrackingConfig,
    RetentionStatus,
};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::{
    CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest, RetainedFileImport,
    RetainedReadLimits,
};
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:long-sentinel-contract";
const SENSOR: &str = "sensor:long-sentinel-contract";
const JPEG: &[u8] =
    include_bytes!("../../../tests/fixtures/media/jpeg/rgb_64x48_colorbars_420.jpg");
const PACKAGE: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");
const PACKAGE_DIGEST: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";
const AVC_MP4: &[u8] = include_bytes!("fixtures/long_dwell_h264/square_300.mp4");
const AVC_RAW: &[u8] = include_bytes!("fixtures/long_dwell_h264/square_300.h264");
const HEVC: &[u8] = include_bytes!("fixtures/hevc_ingest/watch_96x48_moving.h265");

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-long-sentinel-{label}-{}-{attempt}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:long-sentinel-contract".into(),
        operation_id: OperationId::parse("operation:long-sentinel-contract")?,
        principal: "principal:long-sentinel-contract".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(1024 * 1024 * 1024)
            .storage_operations(131_072)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

struct Fixture {
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    request: LongSentinelRequest,
    directory: Directory,
}
impl Fixture {
    fn new(label: &str, bytes: &[u8], extension: &str) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let source = directory.0.join(format!("source.{extension}"));
        fs::write(&source, bytes)?;
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut limits = FileIngestLimits::standard();
        limits.max_segments = 1024;
        limits.chunk_bytes = 1024;
        let receipt = FileIngestAdapter::ingest(
            FileIngestRequest::new(
                &source,
                SensorId::parse(SENSOR)?,
                StreamId::parse("stream:long-sentinel-contract")?,
            )
            .with_limits(limits)
            .with_receive_time(TimestampNs(1_000_000_000_000))
            .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?),
            &cx,
            &mut deployment,
        )?;
        fs::remove_file(source)?;
        Ok(Self {
            deployment,
            cx,
            directory,
            request: LongSentinelRequest {
                import_identity: receipt.import_identity,
                first_segment: 0,
                segment_count: receipt.capsule_count,
                interpretation: ComponentInterpretation::YCbCr,
                minimum_score_ppm: None,
            },
        })
    }
    fn package(&self, scalar: &ScalarExecCx) -> Test<RgbDetectorPackage> {
        Ok(RgbDetectorPackage::load(
            PACKAGE,
            ContentDigest::parse(PACKAGE_DIGEST)?,
            1 << 36,
            &self.cx,
            scalar,
        )?)
    }
    fn snapshot(&self) -> (LedgerAnchor, ContentDigest, usize) {
        (
            self.deployment.current_anchor().clone(),
            self.deployment.effects().last_root(),
            self.deployment.publisher().spool().digests().count(),
        )
    }
    fn late_chunk(&self) -> Test<ContentDigest> {
        let source = RetainedFileImport::open(
            &self.deployment,
            self.request.import_identity,
            RetainedReadLimits::default(),
            &self.cx,
        )?;
        let last = *source
            .manifest()
            .ordered_chunks
            .last()
            .ok_or("source chunk")?;
        assert_ne!(last, source.manifest().ordered_chunks[0]);
        Ok(last)
    }
}

fn config(every_frames: usize, burst_frames: usize, max_inferences: usize) -> LongSentinelConfig {
    LongSentinelConfig {
        every_frames,
        burst_frames,
        max_inferences,
    }
}
fn video_limits(width: u32, height: u32, pictures: usize) -> LongSentinelLimits {
    let mut limits = LongSentinelLimits::default();
    limits.package.h264.max_width = width;
    limits.package.h264.max_height = height;
    limits.package.h264.max_macroblocks = width.div_ceil(16) * height.div_ceil(16);
    limits.package.h264.max_pictures = pictures as u64;
    limits.package.h265.max_width = width;
    limits.package.h265.max_height = height;
    limits.package.h265.max_luma_samples = u64::from(width) * u64::from(height);
    limits.package.h265.max_pictures = pictures as u64;
    limits.maximum_pixel_samples = pictures as u64 * u64::from(width) * u64::from(height);
    limits
}

#[test]
fn schedule_oracle_covers_long_periods_full_bursts_compact_complement_and_overflow() -> Test {
    for count in [64, 65, 128, 129, 170, MAX_LONG_WATCH_FRAMES] {
        for every in [1, 3, 65, 130, MAX_LONG_WATCH_FRAMES] {
            for burst in [1, 3].into_iter().filter(|burst| *burst <= every) {
                for budget in [burst, 64] {
                    let plan = LongSentinelPlan::new(37, count, config(every, burst, budget))?;
                    let selected = plan.selected_segments();
                    let expected: BTreeSet<_> = (0..count)
                        .filter(|offset| {
                            let group = offset / every;
                            offset % every < burst
                                && group * every + burst <= count
                                && (group + 1) * burst <= budget
                        })
                        .map(|offset| 37 + offset)
                        .collect();
                    assert_eq!(selected, expected);
                    let ranges = plan.unsampled_ranges();
                    assert!(ranges.len() <= 65);
                    let mut previous_end = 37;
                    let mut unsampled = 0;
                    for range in ranges {
                        assert!(range.segment_count > 0);
                        assert!(range.first_segment >= previous_end);
                        let end = range.first_segment + range.segment_count;
                        assert!(end <= 37 + count);
                        assert!(selected.range(range.first_segment..end).next().is_none());
                        previous_end = end;
                        unsampled += range.segment_count;
                    }
                    assert_eq!(selected.len() + unsampled, count);
                    let reserved = plan.reservation(&LongSentinelLimits::default())?;
                    assert_eq!(reserved.inferences, selected.len());
                    assert!(reserved.inferences <= budget);
                }
            }
        }
    }
    let plan = LongSentinelPlan::new(0, 170, config(65, 3, 7))?;
    assert_eq!(
        plan.selected_segments(),
        BTreeSet::from([0, 1, 2, 65, 66, 67])
    );
    assert!(!plan.bursts()[2].admitted);
    let mut overflow = LongSentinelLimits::default();
    overflow.package.run.execution.max_macs = u64::MAX;
    assert!(plan.reservation(&overflow).is_err());
    overflow = LongSentinelLimits::default();
    overflow.package.run.preprocess.max_macs = u64::MAX;
    assert!(plan.reservation(&overflow).is_err());
    overflow = LongSentinelLimits::default();
    overflow.package.run.maximum_output_bytes = usize::MAX;
    assert!(plan.reservation(&overflow).is_err());
    assert!(LongSentinelPlan::new(usize::MAX, 2, config(1, 1, 1)).is_err());
    assert!(LongSentinelPlan::new(0, MAX_LONG_WATCH_FRAMES + 1, config(1, 1, 1)).is_err());
    assert!(LongSentinelPlan::new(0, 170, config(130, 3, 2)).is_err());
    Ok(())
}

#[test]
fn native_avc_and_hevc_replay_the_original_prefix_for_non_keyframe_late_children() -> Test {
    // Concatenation is valid raw HEVC: each retained 14-picture sequence starts with its own
    // VPS/SPS/PPS and IDR. No container bytes are concatenated and no encoder runs in this test.
    let hevc = HEVC.repeat(10);
    for (name, bytes, extension, count, width, height, period) in [
        ("avc", AVC_MP4, "mp4", 300, 48, 32, 130),
        ("hevc", hevc.as_slice(), "h265", 140, 96, 48, 65),
    ] {
        let mut f = Fixture::new(name, bytes, extension)?;
        assert_eq!(f.request.segment_count, count);
        let scalar = ScalarExecCx::new();
        let package = f.package(&scalar)?;
        let limits = video_limits(width, height, count);
        let before = f.snapshot();
        let guarded = context(f.deployment.root())?;
        guarded.set_cancel_at_checkpoint(if name == "avc" {
            "recorded_h264:nal"
        } else {
            "recorded_h265:nal"
        });
        let mut less_than_one_picture = limits;
        less_than_one_picture.maximum_pixel_samples = u64::from(width) * u64::from(height) - 1;
        assert!(
            run_long_sentinel_detection(
                &f.deployment,
                &package,
                &f.request,
                config(period, 1, 3),
                &less_than_one_picture,
                &guarded,
                &scalar
            )
            .is_err()
        );
        // The armed first picture-NAL checkpoint is never reached: unused encoded-byte
        // allowance cannot fund one extra unit of conservative coded-luma capacity.
        assert!(!guarded.is_cancelled());
        let report = run_long_sentinel_detection(
            &f.deployment,
            &package,
            &f.request,
            config(period, 1, 3),
            &limits,
            &f.cx,
            &scalar,
        )?;
        assert_eq!(f.snapshot(), before);
        assert_eq!(report.usage().decoded_frames, count);
        assert_eq!(
            report.usage().pixel_samples,
            count as u64 * u64::from(width) * u64::from(height)
        );
        assert_eq!(
            report.usage().video_coded_luma_capacity,
            report.usage().pixel_samples
        );
        assert!(report.usage().video_encoded_bytes > 0);
        assert_eq!(
            report.usage().video_decode_work_units,
            report.usage().video_encoded_bytes + report.usage().video_coded_luma_capacity
        );
        assert_eq!(report.usage().inferences, 3);
        assert_eq!(
            report
                .reports()
                .iter()
                .map(|child| child.first_segment)
                .collect::<Vec<_>>(),
            [0, period, 2 * period]
        );
        assert!(report.reports()[2].first_segment >= 128);
        assert!(report.reports().iter().all(|child| child.frames.len() == 1
            && child.frames[0].color == "ycbcr420_bt601_limited_rgb"));
        // A child is a valid evidence burst but not a standalone decoder starting point.
        assert!(
            run_package_detection(
                &f.deployment,
                &package,
                &PackageDetectRequest {
                    import_identity: f.request.import_identity,
                    first_segment: period,
                    segment_count: 1,
                    interpretation: ComponentInterpretation::YCbCr,
                    minimum_score_ppm: None,
                },
                &limits.package,
                &f.cx,
                &scalar
            )
            .is_err()
        );
        let retained =
            retain_long_sentinel_detection(&mut f.deployment, &package, PACKAGE, &report, &f.cx)?;
        let digest = report.digest();
        let json = report.json().to_owned();
        let root = retained.root();
        drop(retained);
        drop(package);
        drop(report);
        let deployment_root = f.deployment.root().to_path_buf();
        drop(f.deployment);
        f.cx.drain_and_finalize();
        f.cx = context(&deployment_root)?;
        f.deployment = ReferenceDeployment::reopen(&deployment_root, SITE, &f.cx)?;
        let before = f.snapshot();
        let ceilings = LongSentinelReplayLimits {
            execution: limits,
            ..Default::default()
        };
        assert_eq!(
            RetainedLongSentinel::open(&f.deployment, digest, &ceilings, &f.cx)?.root(),
            root
        );
        let replayed = rerun_long_sentinel_detection(
            &f.deployment,
            digest,
            &ceilings,
            &f.cx,
            &ScalarExecCx::new(),
        )?;
        assert_eq!(replayed.digest(), digest);
        assert_eq!(replayed.json(), json);
        assert_eq!(f.snapshot(), before);
        assert_eq!(f.deployment.effects().operations().count(), 0);
    }
    Ok(())
}

#[test]
fn an_unselected_late_video_suffix_and_decode_ahead_budget_cannot_be_hidden() -> Test {
    let f = Fixture::new("late-avc", AVC_RAW, "h264")?;
    let scalar = ScalarExecCx::new();
    let package = f.package(&scalar)?;
    let limits = video_limits(48, 32, 300);
    let before = f.snapshot();
    let mut too_small = limits;
    too_small.maximum_pixel_samples = 48 * 32 - 1;
    assert!(
        run_long_sentinel_detection(
            &f.deployment,
            &package,
            &f.request,
            config(300, 1, 1),
            &too_small,
            &f.cx,
            &scalar
        )
        .is_err()
    );
    let mut one_frame = limits;
    one_frame.maximum_pixel_samples = 48 * 32;
    // Even one selected picture cannot renew the conservative pre-codec allowance for
    // reordering or the remaining unsampled reference pictures.
    assert!(
        run_long_sentinel_detection(
            &f.deployment,
            &package,
            &f.request,
            config(300, 1, 1),
            &one_frame,
            &f.cx,
            &scalar
        )
        .is_err()
    );
    let path = f
        .deployment
        .publisher()
        .spool()
        .object_path(f.late_chunk()?);
    let mut bytes = fs::read(&path)?;
    *bytes.last_mut().ok_or("empty retained source")? ^= 0x80;
    fs::write(path, bytes)?;
    assert!(
        run_long_sentinel_detection(
            &f.deployment,
            &package,
            &f.request,
            config(300, 1, 1),
            &limits,
            &f.cx,
            &scalar
        )
        .is_err()
    );
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn sparse_jpeg_bursts_share_head_codec_source_pixel_and_complete_report_allowances() -> Test {
    let f = Fixture::new("shared-budget", &JPEG.repeat(170), "mjpeg")?;
    let scalar = ScalarExecCx::new();
    let package = f.package(&scalar)?;
    let schedule = config(130, 1, 2);
    let limits = LongSentinelLimits::default();
    let before = f.snapshot();
    let report = run_long_sentinel_detection(
        &f.deployment,
        &package,
        &f.request,
        schedule,
        &limits,
        &f.cx,
        &scalar,
    )?;
    let used = *report.usage();
    assert_eq!(used.decoded_frames, 2);
    assert_eq!(used.pixel_samples, 2 * 64 * 48);
    assert_eq!(used.inferences, 2);
    assert_eq!(report.reports()[1].first_segment, 130);
    assert!(
        used.detection_work_units > 1 && used.jpeg_work_units > 1 && used.source_chunk_bytes > 1
    );
    for owner in ["head", "jpeg", "source", "pixels", "report"] {
        let mut narrow = limits;
        match owner {
            "head" => narrow.package.detection_work_units = used.detection_work_units - 1,
            "jpeg" => narrow.package.jpeg_work_units = used.jpeg_work_units - 1,
            "source" => narrow.maximum_source_chunk_bytes = used.source_chunk_bytes - 1,
            "pixels" => narrow.maximum_pixel_samples = used.pixel_samples - 1,
            "report" => narrow.maximum_report_bytes = 1,
            _ => unreachable!(),
        }
        assert!(
            run_long_sentinel_detection(
                &f.deployment,
                &package,
                &f.request,
                schedule,
                &narrow,
                &f.cx,
                &scalar
            )
            .is_err(),
            "{owner}"
        );
        assert_eq!(f.snapshot(), before, "{owner}");
    }
    let mut exact = limits;
    exact.package.detection_work_units = used.detection_work_units;
    exact.package.jpeg_work_units = used.jpeg_work_units;
    exact.maximum_source_chunk_bytes = used.source_chunk_bytes;
    exact.maximum_pixel_samples = used.pixel_samples;
    let admitted = run_long_sentinel_detection(
        &f.deployment,
        &package,
        &f.request,
        schedule,
        &exact,
        &f.cx,
        &scalar,
    )?;
    assert_eq!(admitted.usage(), &used);
    assert_eq!(admitted.reports()[0].digest, report.reports()[0].digest);
    assert_eq!(admitted.reports()[1].digest, report.reports()[1].digest);
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn foreign_authority_and_cancellation_never_return_partial_inference_or_retention() -> Test {
    let mut f = Fixture::new("cancellation", &JPEG.repeat(3), "mjpeg")?;
    let scalar = ScalarExecCx::new();
    let package = f.package(&scalar)?;
    let schedule = config(3, 1, 1);
    let limits = LongSentinelLimits::default();
    let before = f.snapshot();
    let other = Directory::new("foreign-authority")?;
    let foreign = context(&other.0.join("deployment"))?;
    assert!(
        run_long_sentinel_detection(
            &f.deployment,
            &package,
            &f.request,
            schedule,
            &limits,
            &foreign,
            &scalar
        )
        .is_err()
    );
    for stage in [
        "long_sentinel:begin",
        "long_sentinel:jpeg",
        "package_detect:frame",
        "long_sentinel:drained",
        "long_sentinel:complete",
    ] {
        let cancelled = context(f.deployment.root())?;
        cancelled.set_cancel_at_checkpoint(stage);
        assert!(
            run_long_sentinel_detection(
                &f.deployment,
                &package,
                &f.request,
                schedule,
                &limits,
                &cancelled,
                &scalar
            )
            .is_err(),
            "{stage}"
        );
        assert!(cancelled.is_drain_completed(), "{stage}");
        assert_eq!(f.snapshot(), before);
    }
    let cancelled = ScalarExecCx::new();
    cancelled.request_cancellation();
    assert!(matches!(
        run_long_sentinel_detection(
            &f.deployment,
            &package,
            &f.request,
            schedule,
            &limits,
            &f.cx,
            &cancelled
        ),
        Err(PackageDetectError::Cancelled)
    ));
    assert!(cancelled.is_drain_completed());
    let report = run_long_sentinel_detection(
        &f.deployment,
        &package,
        &f.request,
        schedule,
        &limits,
        &f.cx,
        &scalar,
    )?;
    let cancelled = context(f.deployment.root())?;
    cancelled.set_cancel_at_checkpoint("long_sentinel_retained:preflight_complete");
    assert!(
        retain_long_sentinel_detection(&mut f.deployment, &package, PACKAGE, &report, &cancelled)
            .is_err()
    );
    assert!(cancelled.is_drain_completed());
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn retention_preflights_all_source_and_model_custody_and_current_privacy_before_writes() -> Test {
    let mut f = Fixture::new("preflight", &JPEG.repeat(170), "mjpeg")?;
    let scalar = ScalarExecCx::new();
    let package = f.package(&scalar)?;
    let report = run_long_sentinel_detection(
        &f.deployment,
        &package,
        &f.request,
        config(170, 1, 1),
        &LongSentinelLimits::default(),
        &f.cx,
        &scalar,
    )?;
    let before = f.snapshot();
    assert!(
        retain_long_sentinel_detection(
            &mut f.deployment,
            &package,
            b"wrong archive",
            &report,
            &f.cx
        )
        .is_err()
    );
    assert_eq!(f.snapshot(), before);
    let source_path = f
        .deployment
        .publisher()
        .spool()
        .object_path(f.late_chunk()?);
    let original_source = fs::read(&source_path)?;
    fs::remove_file(&source_path)?;
    assert!(
        retain_long_sentinel_detection(&mut f.deployment, &package, PACKAGE, &report, &f.cx)
            .is_err()
    );
    assert_eq!(f.snapshot(), before);
    fs::write(&source_path, &original_source)?;
    let source = RetainedFileImport::open(
        &f.deployment,
        f.request.import_identity,
        RetainedReadLimits::default(),
        &f.cx,
    )?;
    let capsule_object = format!(
        "object:capsule:{}",
        source.manifest().segment_spans[169].capsule_id
    );
    let capsule_digest = f
        .deployment
        .ledger()
        .batches()
        .iter()
        .flat_map(|batch| &batch.deltas)
        .find(|delta| delta.object_id.as_str() == capsule_object)
        .ok_or("unselected source capsule")?
        .payload_digest;
    let capsule_path = f.deployment.publisher().spool().object_path(capsule_digest);
    let original_capsule = fs::read(&capsule_path)?;
    fs::remove_file(&capsule_path)?;
    assert!(
        retain_long_sentinel_detection(&mut f.deployment, &package, PACKAGE, &report, &f.cx)
            .is_err()
    );
    assert_eq!(f.snapshot(), before);
    fs::write(&capsule_path, &original_capsule)?;
    let retained =
        retain_long_sentinel_detection(&mut f.deployment, &package, PACKAGE, &report, &f.cx)?;
    let before = f.snapshot();
    let archive_path = f
        .deployment
        .publisher()
        .spool()
        .object_path(retained.package_digest());
    let archive_object = fs::read(&archive_path)?;
    for (path, bytes) in [
        (&archive_path, &archive_object),
        (&source_path, &original_source),
        (&capsule_path, &original_capsule),
    ] {
        fs::remove_file(path)?;
        assert!(
            RetainedLongSentinel::open(
                &f.deployment,
                report.digest(),
                &LongSentinelReplayLimits::default(),
                &f.cx
            )
            .is_err()
        );
        assert!(
            rerun_long_sentinel_detection(
                &f.deployment,
                report.digest(),
                &LongSentinelReplayLimits::default(),
                &f.cx,
                &scalar
            )
            .is_err()
        );
        assert_eq!(f.snapshot(), before);
        fs::write(path, bytes)?;
    }
    // Policy changes invalidate delayed computations and retained reads alike.
    let mask = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [64, 48], &[[0, 0, 64, 1]])?;
    let approval = preview_mask(&f.deployment, &mask)?.approval;
    declare_mask(&mut f.deployment, &mask, approval, &f.cx)?;
    let before = f.snapshot();
    assert!(
        retain_long_sentinel_detection(&mut f.deployment, &package, PACKAGE, &report, &f.cx)
            .is_err()
    );
    assert!(
        RetainedLongSentinel::open(
            &f.deployment,
            report.digest(),
            &LongSentinelReplayLimits::default(),
            &f.cx
        )
        .is_err()
    );
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn root_last_cancellation_retries_once_and_retained_children_keep_cold_event_access() -> Test {
    let mut f = Fixture::new("root-last", &JPEG.repeat(170), "mjpeg")?;
    let scalar = ScalarExecCx::new();
    let package = f.package(&scalar)?;
    let report = run_long_sentinel_detection(
        &f.deployment,
        &package,
        &f.request,
        config(130, 3, 6),
        &LongSentinelLimits::default(),
        &f.cx,
        &scalar,
    )?;
    let cancelled = context(f.deployment.root())?;
    cancelled.set_cancel_at_checkpoint("long_sentinel_retained:commit");
    assert!(
        retain_long_sentinel_detection(&mut f.deployment, &package, PACKAGE, &report, &cancelled)
            .is_err()
    );
    assert!(cancelled.is_drain_completed());
    assert!(matches!(
        RetainedLongSentinel::open(
            &f.deployment,
            report.digest(),
            &LongSentinelReplayLimits::default(),
            &f.cx
        ),
        Err(LongSentinelRetentionError::Unavailable)
    ));
    let retained =
        retain_long_sentinel_detection(&mut f.deployment, &package, PACKAGE, &report, &f.cx)?;
    assert_eq!(retained.status(), RetentionStatus::Retained);
    let before = f.snapshot();
    let retry =
        retain_long_sentinel_detection(&mut f.deployment, &package, PACKAGE, &report, &f.cx)?;
    assert_eq!(retry.status(), RetentionStatus::AlreadyRetained);
    assert_eq!(retry.root(), retained.root());
    assert_eq!(retry.authority_anchor(), retained.authority_anchor());
    assert_eq!(f.snapshot(), before);
    let tracking = PackageTrackingConfig {
        confirmation_hits: 3,
        maximum_missed_frames: 1,
        minimum_iou_ppm: 100_000,
    };
    let first = PackageAnalysisReport::read(
        &f.deployment,
        retained.child_reports()[0],
        "tie",
        tracking,
        &f.cx,
    )?;
    let second = PackageAnalysisReport::read(
        &f.deployment,
        retained.child_reports()[1],
        "tie",
        tracking,
        &f.cx,
    )?;
    let track = first
        .tracks()
        .iter()
        .find(|track| track.confirmed)
        .ok_or("fixture track")?
        .identity;
    assert!(second.tracks().iter().all(|other| other.identity != track));
    let proposal = PackageEventProposal::prepare(
        &f.deployment,
        first.encoded(),
        first.digest(),
        track,
        &f.cx,
    )?;
    let receipt = proposal.publish(&mut f.deployment, proposal.digest(), &f.cx)?;
    let root = f.deployment.root().to_path_buf();
    drop(package);
    drop(report);
    drop(retained);
    drop(retry);
    drop(f.deployment);
    f.cx.drain_and_finalize();
    f.cx = context(&root)?;
    f.deployment = ReferenceDeployment::reopen(&root, SITE, &f.cx)?;
    let before = f.snapshot();
    let event = PackageEvent::open(&f.deployment, &receipt.event.event_id, &f.cx)?;
    assert_eq!(event.event(), &receipt.event);
    assert_eq!(event.event().kind, EventKind::Unclassified);
    assert_eq!(event.event().state, EventState::Indeterminate);
    assert!(event.event().decision_path.abstained);
    assert_eq!(f.deployment.effects().operations().count(), 0);
    assert_eq!(f.snapshot(), before);
    assert!(!f.directory.0.join("source.mjpeg").exists());
    Ok(())
}

#![forbid(unsafe_code)]
//! Cold retained RTP and the committed verified neural model, never supplied boxes.
mod rtpdump_support;

use fss_core::{ContentDigest, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::rtpdump::detect::RtpDetectionRequest;
use fss_reference::ingest::rtpdump::import::{
    RtpImportLimits, RtpImportScope, prepare_rtp_import, publish_rtp_import,
};
use fss_reference::ingest::rtpdump::recovery::decode::RetainedRtpDecodeRequest;
use fss_reference::ingest::rtpdump::recovery::{
    RecoveredRtpImport, RtpRecoveryPolicy, inspect_rtp_import,
};
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};
use rtpdump_support::*;
use std::path::PathBuf;

const PACKAGE: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");
const PACKAGE_SHA: &str = "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";
const SITE: &str = "site:rtp-sampled-tracking";
const SENSOR: &str = "sensor:rtp-sampled-tracking";
struct Fixture {
    dep: ReferenceDeployment,
    root: ContentDigest,
    package: RgbDetectorPackage,
    cx: ReplayCx,
    scalar: ScalarExecCx,
    dir: PathBuf,
}
impl Fixture {
    fn new(label: &str, bytes: &[u8]) -> Result<Self, Error> {
        let base = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
        std::fs::create_dir_all(base)?;
        for attempt in 0..1000 {
            let dir = base.join(format!(
                "rtp-sampled-tracking-{label}-{}-{attempt}",
                std::process::id()
            ));
            match std::fs::create_dir(&dir) {
                Ok(()) => {
                    let cx = cx()?;
                    let scalar = ScalarExecCx::new();
                    let mut dep = ReferenceDeployment::open(&dir, SITE, &cx)?;
                    let plan = prepare_rtp_import(
                        bytes,
                        RtpImportScope {
                            sensor: SensorId::parse(SENSOR)?,
                            stream: StreamId::parse("stream:rtp-sampled-tracking")?,
                            receive_time: TimestampNs(1_000_000_000),
                        },
                        config_for(7),
                        RtpImportLimits::default(),
                        &cx,
                    )?;
                    let root = publish_rtp_import(plan, &cx, &mut dep)?.root();
                    drop(dep);
                    let dep = ReferenceDeployment::reopen(&dir, SITE, &cx)?;
                    let package = RgbDetectorPackage::load(
                        PACKAGE,
                        PACKAGE_SHA.parse()?,
                        1 << 40,
                        &cx,
                        &scalar,
                    )?;
                    return Ok(Self {
                        dep,
                        root,
                        package,
                        cx,
                        scalar,
                        dir,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("test directory bound".into())
    }
    fn retained(&self, ingress: u128) -> Result<RecoveredRtpImport, Error> {
        Ok(inspect_rtp_import(
            self.root,
            ingress,
            RtpRecoveryPolicy::default(),
            &self.cx,
            &self.dep,
        )?)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
fn request(r: &RecoveredRtpImport, cx: &ReplayCx) -> Result<RtpDetectionRequest, Error> {
    let pair = r.h264_parameters(cx)?.unique_pair().ok_or("parameters")?;
    Ok(RtpDetectionRequest::new(RetainedRtpDecodeRequest::new(
        pair,
    )))
}

use fss_reference::ingest::activity::ActivityPolicy;
use fss_reference::ingest::pixel_change::PixelChangeConfig;
use fss_reference::ingest::rtpdump::detect::cascade::RtpCascadeRequest;
use fss_reference::ingest::rtpdump::track::sampled::*;
use fss_reference::ingest::rtpdump::track::{
    RtpPackageTracker, RtpTrackReset, RtpTrackingError, RtpTrackingLimits, RtpTrackingRequest,
    RtpTrackingStep,
};
use fss_reference::ingest::tracker::TrackerConfig;

fn config() -> TrackerConfig {
    TrackerConfig {
        min_hits: 2,
        max_misses: 2,
        iou_threshold: 0.1,
        process_noise: 1.0,
        measurement_noise: 1.0,
    }
}
fn sampled_request(
    f: &Fixture,
    r: &RecoveredRtpImport,
    stride: u32,
) -> Result<RtpSampledTrackingRequest, Error> {
    Ok(RtpSampledTrackingRequest {
        cascade: RtpCascadeRequest::new(
            request(r, &f.cx)?,
            ActivityPolicy {
                change: PixelChangeConfig {
                    minimum_delta: 255,
                    minimum_changed_pixels: 4_194_304,
                    minimum_changed_fraction_ppm: 0,
                },
                sentinel_stride: stride,
                post_activity_frames: 0,
            },
            64_000_000,
        ),
        class_index: 0,
        tracker: config(),
        limits: RtpTrackingLimits::default(),
    })
}
fn sampled_collect(
    owner: &mut RtpSampledTracker<'_>,
    f: &Fixture,
) -> Result<Vec<RtpSampledTrackFrame>, Error> {
    let mut frames = Vec::new();
    for _ in 0..20_000 {
        match owner.step(&f.dep, &f.cx, &f.scalar)? {
            RtpSampledTrackingStep::Frame(frame) => frames.push(frame),
            RtpSampledTrackingStep::Ended(stats) => {
                assert_eq!(stats.delivered, frames.len());
                return Ok(frames);
            }
            RtpSampledTrackingStep::Progress { .. } => {}
        }
    }
    Err("sampled tracking fixture step bound".into())
}
fn first(owner: &mut RtpSampledTracker<'_>, f: &Fixture) -> Result<RtpSampledTrackFrame, Error> {
    for _ in 0..20_000 {
        match owner.step(&f.dep, &f.cx, &f.scalar)? {
            RtpSampledTrackingStep::Frame(frame) => return Ok(frame),
            RtpSampledTrackingStep::Ended(_) => return Err("early sampled end".into()),
            _ => {}
        }
    }
    Err("sampled tracking fixture step bound".into())
}
fn refused(owner: &mut RtpSampledTracker<'_>, f: &Fixture) -> Result<RtpTrackingError, Error> {
    for _ in 0..20_000 {
        match owner.step(&f.dep, &f.cx, &f.scalar) {
            Err(error) => return Ok(error),
            Ok(RtpSampledTrackingStep::Ended(_)) => return Err("expected refusal".into()),
            _ => {}
        }
    }
    Err("sampled tracking fixture step bound".into())
}

#[test]
fn sparse_tracking_preserves_every_receipt_skip_and_disjoint_association_epoch() -> TestResult {
    let f = Fixture::new("sampled-track-sparse", &real_dump(true))?;
    let anchor = f.dep.current_anchor().clone();
    let mut runs = Vec::new();
    for ingress in [1, 777] {
        let r = f.retained(ingress)?;
        let mut owner = RtpSampledTracker::new(
            &r,
            &f.package,
            sampled_request(&f, &r, 2)?,
            &f.dep,
            &f.cx,
            &f.scalar,
        )?;
        let frames = sampled_collect(&mut owner, &f)?;
        assert!(owner.stats().complete());
        assert!(!owner.stats().exhaustive());
        assert!(!owner.stats().tracking.complete());
        assert_eq!(
            (
                owner.stats().delivered,
                owner.stats().skipped,
                owner.stats().tracking.frames
            ),
            (4, 2, 2)
        );
        let mut previous = None;
        for (index, frame) in frames.iter().enumerate() {
            assert_eq!(frame.predecessor(), previous);
            assert_eq!(
                frame.sample().decision().observation().output_index,
                index as u64
            );
            assert_eq!(frame.sample().decision().observation().source_root, f.root);
            assert_eq!(
                frame.sample().receipt().digest(),
                frame.sample().decision().observation().frame_receipt
            );
            if index % 2 == 0 {
                let update = frame.association().ok_or("selected association")?;
                assert_eq!(update.epoch(), (index / 2) as u64);
                assert_eq!(
                    update.reset(),
                    Some(if index == 0 {
                        RtpTrackReset::Baseline
                    } else {
                        RtpTrackReset::DisplayGap
                    })
                );
                assert!(update.observations().iter().all(|o| o.hits == 1));
                assert_eq!(
                    frame
                        .sample()
                        .detection()
                        .ok_or("selected detection")?
                        .source()
                        .output_index,
                    index
                );
            } else {
                assert!(frame.association().is_none());
                assert!(frame.sample().detection().is_none());
            }
            previous = Some(frame.digest());
        }
        assert_eq!(owner.stats().last_result, previous);
        runs.push(
            frames
                .iter()
                .map(RtpSampledTrackFrame::digest)
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(runs[0], runs[1]);
    assert_eq!(f.dep.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn contiguous_selected_frames_use_the_exhaustive_solve_and_complete_report_indices() -> TestResult {
    let f = Fixture::new("sampled-track-exhaustive", &real_dump(false))?;
    let r = f.retained(1)?;
    let req = sampled_request(&f, &r, 1)?;
    let ordinary = RtpTrackingRequest {
        detection: req.cascade.detection,
        class_index: req.class_index,
        tracker: req.tracker.clone(),
        limits: req.limits,
    };
    let mut expected = RtpPackageTracker::new(&r, &f.package, ordinary, &f.dep, &f.cx, &f.scalar)?;
    let mut owner = RtpSampledTracker::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
    let actual = sampled_collect(&mut owner, &f)?;
    assert!(owner.stats().exhaustive());
    let mut index = 0;
    for _ in 0..20_000 {
        match expected.step(&f.dep, &f.cx, &f.scalar)? {
            RtpTrackingStep::Frame(frame) => {
                let sampled = actual.get(index).ok_or("extra exhaustive frame")?;
                let update = sampled.association().ok_or("all-selected update")?;
                assert_eq!(
                    frame.detected().digest(),
                    sampled.sample().detection().ok_or("inferred")?.digest()
                );
                assert_eq!(frame.epoch(), update.epoch());
                assert_eq!(frame.reset(), update.reset());
                assert_eq!(frame.active_tracks(), update.active_tracks());
                assert_eq!(frame.deleted_tracks(), update.deleted_tracks());
                let project = |o: &fss_reference::ingest::rtpdump::track::RtpTrackObservation| {
                    (o.local_id, o.detection_index, o.status, o.hits)
                };
                assert_eq!(
                    frame.observations().iter().map(project).collect::<Vec<_>>(),
                    update
                        .observations()
                        .iter()
                        .map(project)
                        .collect::<Vec<_>>()
                );
                index += 1;
            }
            RtpTrackingStep::Ended(stats) => {
                assert!(stats.complete());
                break;
            }
            _ => {}
        }
    }
    assert_eq!(index, actual.len());
    assert_eq!(
        owner.stats().tracking.assignments_reserved,
        expected.stats().assignments_reserved
    );
    assert_eq!(
        owner.stats().tracking.assignment_work_reserved,
        expected.stats().assignment_work_reserved
    );
    Ok(())
}

#[test]
fn selected_update_limits_do_not_charge_skips_or_refill_after_them() -> TestResult {
    let f = Fixture::new("sampled-track-limits", &real_dump(false))?;
    let r = f.retained(1)?;
    let mut req = sampled_request(&f, &r, 2)?;
    req.limits.max_frames = 1;
    let mut owner = RtpSampledTracker::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
    assert!(matches!(refused(&mut owner, &f)?, RtpTrackingError::Limit));
    let stats = owner.stats();
    assert_eq!(
        (stats.delivered, stats.skipped, stats.tracking.frames),
        (2, 1, 1)
    );
    assert_eq!(stats.sampling.delivered, 3);
    assert!(stats.tracking.ended && !stats.complete());
    for _ in 0..3 {
        assert!(matches!(
            owner.step(&f.dep, &f.cx, &f.scalar)?,
            RtpSampledTrackingStep::Ended(_)
        ));
        assert_eq!(format!("{:?}", owner.stats()), format!("{stats:?}"));
    }
    Ok(())
}

#[test]
fn explicit_required_frames_continue_bursts_but_missing_requirements_prevent_completion()
-> TestResult {
    let f = Fixture::new("sampled-track-required", &real_dump(false))?;
    let r = f.retained(1)?;
    let mut req = sampled_request(&f, &r, 256)?;
    let reason = ContentDigest::sha256(b"owner inclusion request");
    req.cascade.required_frames = vec![(1, reason)];
    let mut owner = RtpSampledTracker::new(&r, &f.package, req.clone(), &f.dep, &f.cx, &f.scalar)?;
    let frames = sampled_collect(&mut owner, &f)?;
    assert!(owner.stats().complete());
    assert_eq!(
        frames[1].association().ok_or("required update")?.reset(),
        None
    );
    assert_eq!(frames[1].sample().decision().required_basis(), Some(reason));
    assert!(frames[2].association().is_none());
    req.cascade.required_frames.push((7, reason));
    let mut incomplete = RtpSampledTracker::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
    sampled_collect(&mut incomplete, &f)?;
    assert!(!incomplete.stats().complete());
    assert_eq!(incomplete.stats().sampling.unobserved_required, 1);
    Ok(())
}

#[test]
fn cancellation_at_skip_delivery_discards_the_joint_result_and_drains_both_owners() -> TestResult {
    let f = Fixture::new("sampled-track-cancel", &real_dump(false))?;
    let r = f.retained(1)?;
    let mut owner = RtpSampledTracker::new(
        &r,
        &f.package,
        sampled_request(&f, &r, 2)?,
        &f.dep,
        &f.cx,
        &f.scalar,
    )?;
    let delivered = first(&mut owner, &f)?;
    f.cx.set_cancel_at_checkpoint("rtp_sampled_track:deliver");
    assert!(matches!(
        refused(&mut owner, &f)?,
        RtpTrackingError::Cancelled
    ));
    assert_eq!(owner.stats().delivered, 1);
    assert_eq!(owner.stats().skipped, 0);
    assert_eq!(owner.stats().last_result, Some(delivered.digest()));
    assert_eq!(owner.stats().sampling.delivered, 2);
    assert!(f.cx.is_drain_completed() && f.scalar.is_drain_completed());
    assert!(!owner.stats().complete());
    Ok(())
}

#[test]
fn privacy_and_original_custody_are_rechecked_even_before_an_inference_skip() -> TestResult {
    for privacy in [false, true] {
        let mut f = Fixture::new("sampled-track-withdraw", &real_dump(false))?;
        let r = f.retained(1)?;
        let mut owner = RtpSampledTracker::new(
            &r,
            &f.package,
            sampled_request(&f, &r, 2)?,
            &f.dep,
            &f.cx,
            &f.scalar,
        )?;
        let delivered = first(&mut owner, &f)?;
        if privacy {
            let dimensions = delivered.sample().decision().observation().dimensions;
            let p = PrivacyMaskPolicy::new(
                SensorId::parse(SENSOR)?,
                dimensions,
                &[[0, 0, dimensions[0], dimensions[1]]],
            )?;
            let approval = preview_mask(&f.dep, &p)?.approval;
            declare_mask(&mut f.dep, &p, approval, &f.cx)?;
        } else {
            let chunk = *r.report().chunk_digests().first().ok_or("source chunk")?;
            std::fs::remove_file(f.dep.publisher().spool().object_path(chunk))?;
        }
        let error = refused(&mut owner, &f)?;
        assert!(
            matches!(error, RtpTrackingError::StaleBasis) && privacy
                || matches!(error, RtpTrackingError::Detection(_)) && !privacy
        );
        assert_eq!(owner.stats().delivered, 1);
        assert_eq!(owner.stats().skipped, 0);
        assert_eq!(owner.stats().last_result, Some(delivered.digest()));
        assert!(!owner.stats().complete());
    }
    Ok(())
}

#[test]
fn source_recovery_retains_gap_history_in_sampled_association() -> TestResult {
    let mut packets = packetize(2, 100, 65534, 7, 90000, 0);
    let missing = packets.iter().position(|p| p.vcl).ok_or("IDR")?;
    packets.remove(missing);
    let f = Fixture::new("sampled-track-source-gap", &dump_planned(&packets))?;
    let r = f.retained(1)?;
    let mut owner = RtpSampledTracker::new(
        &r,
        &f.package,
        sampled_request(&f, &r, 2)?,
        &f.dep,
        &f.cx,
        &f.scalar,
    )?;
    let frames = sampled_collect(&mut owner, &f)?;
    assert!(!frames.is_empty());
    assert_eq!(
        frames[0].association().ok_or("recovery baseline")?.reset(),
        Some(RtpTrackReset::SourceGap)
    );
    assert!(owner.stats().sampling.detection.native.refusals > 0);
    assert!(!owner.stats().complete());
    Ok(())
}

#[test]
fn invalid_tracking_admission_precedes_any_additional_source_read() -> TestResult {
    let f = Fixture::new("sampled-track-invalid", &real_dump(false))?;
    let r = f.retained(1)?;
    let req = sampled_request(&f, &r, 2)?;
    let chunk = *r.report().chunk_digests().first().ok_or("source chunk")?;
    std::fs::remove_file(f.dep.publisher().spool().object_path(chunk))?;
    for class in [false, true] {
        let mut invalid = req.clone();
        if class {
            invalid.class_index = f.package.spec().labels.len();
        } else {
            invalid.limits.max_frames = 0;
        }
        assert!(matches!(
            RtpSampledTracker::new(&r, &f.package, invalid, &f.dep, &f.cx, &f.scalar),
            Err(RtpTrackingError::InvalidRequest)
        ));
    }
    Ok(())
}

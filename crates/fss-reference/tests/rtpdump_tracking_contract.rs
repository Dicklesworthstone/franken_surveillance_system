#![forbid(unsafe_code)]
//! Native retained source and the committed verified YOLOX package, not injected detections.
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
use fss_reference::ingest::rtpdump::track::*;
use fss_reference::ingest::tracker::TrackStatus;
use fss_reference::ingest::tracker::TrackerConfig;
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};
use rtpdump_support::*;
use std::collections::BTreeSet;
use std::path::PathBuf;

const PACKAGE: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");
const PACKAGE_SHA: &str = "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";
const SITE: &str = "site:rtp-tracking";
const SENSOR: &str = "sensor:rtp-tracking";
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
                "rtp-tracking-{label}-{}-{attempt}",
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
                            stream: StreamId::parse("stream:rtp-tracking")?,
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
fn request(r: &RecoveredRtpImport, cx: &ReplayCx) -> Result<RtpTrackingRequest, Error> {
    let pair = r.h264_parameters(cx)?.unique_pair().ok_or("parameters")?;
    Ok(RtpTrackingRequest {
        detection: RtpDetectionRequest::new(RetainedRtpDecodeRequest::new(pair)),
        class_index: 0,
        tracker: TrackerConfig {
            min_hits: 2,
            max_misses: 2,
            iou_threshold: 0.1,
            process_noise: 1.0,
            measurement_noise: 1.0,
        },
        limits: RtpTrackingLimits::default(),
    })
}
fn collect(owner: &mut RtpPackageTracker<'_>, f: &Fixture) -> Result<Vec<RtpTrackedFrame>, Error> {
    let mut frames = Vec::new();
    for _ in 0..20_000 {
        match owner.step(&f.dep, &f.cx, &f.scalar)? {
            RtpTrackingStep::Frame(frame) => frames.push(frame),
            RtpTrackingStep::Ended(stats) => {
                assert_eq!(stats.frames, frames.len());
                return Ok(frames);
            }
            RtpTrackingStep::Progress { .. } => {}
        }
    }
    Err("fixture progress bound".into())
}
fn until_error(owner: &mut RtpPackageTracker<'_>, f: &Fixture) -> Result<RtpTrackingError, Error> {
    for _ in 0..20_000 {
        match owner.step(&f.dep, &f.cx, &f.scalar) {
            Err(e) => return Ok(e),
            Ok(RtpTrackingStep::Ended(_)) => return Err("expected refusal".into()),
            _ => {}
        }
    }
    Err("fixture progress bound".into())
}

#[test]
fn cold_native_tracking_is_history_linked_reproducible_and_read_only() -> TestResult {
    let f = Fixture::new("cold", &real_dump(true))?;
    let r = f.retained(11)?;
    let before = f.dep.current_anchor().clone();
    let mut owner = RtpPackageTracker::new(
        &r,
        &f.package,
        request(&r, &f.cx)?,
        &f.dep,
        &f.cx,
        &f.scalar,
    )?;
    let frames = collect(&mut owner, &f)?;
    assert_eq!(frames.len(), 4);
    assert!(owner.stats().complete());
    assert!(owner.stats().detection.execution_macs > 0);
    let mut previous = None;
    for (index, frame) in frames.iter().enumerate() {
        assert_eq!(frame.predecessor(), previous);
        assert_eq!(frame.detected().source().output_index, index);
        assert_eq!(frame.detected().source().root, f.root);
        assert_eq!(frame.epoch(), 0);
        assert_eq!(
            frame.reset(),
            if index == 0 {
                Some(RtpTrackReset::Baseline)
            } else {
                None
            }
        );
        let all = frame.detected().detections().detections();
        let selected: BTreeSet<_> = all
            .iter()
            .enumerate()
            .filter_map(|(i, d)| (d.class_index() == 0).then_some(i))
            .collect();
        assert_eq!(
            selected,
            frame
                .observations()
                .iter()
                .map(|o| o.detection_index)
                .collect::<BTreeSet<_>>()
        );
        assert!(
            frame
                .observations()
                .iter()
                .all(|o| o.status != TrackStatus::Lost)
        );
        previous = Some(frame.digest());
    }
    let reopened = f.retained(999)?;
    let mut replay = RtpPackageTracker::new(
        &reopened,
        &f.package,
        request(&reopened, &f.cx)?,
        &f.dep,
        &f.cx,
        &f.scalar,
    )?;
    let again = collect(&mut replay, &f)?;
    assert_eq!(
        frames
            .iter()
            .map(RtpTrackedFrame::digest)
            .collect::<Vec<_>>(),
        again
            .iter()
            .map(RtpTrackedFrame::digest)
            .collect::<Vec<_>>()
    );
    assert_eq!(f.dep.current_anchor(), &before);
    Ok(())
}

#[test]
fn class_and_numerical_policy_change_recipe_not_native_receipts() -> TestResult {
    let f = Fixture::new("selection", &real_dump(false))?;
    let r = f.retained(1)?;
    let base = request(&r, &f.cx)?;
    let mut owner = RtpPackageTracker::new(&r, &f.package, base.clone(), &f.dep, &f.cx, &f.scalar)?;
    let original = collect(&mut owner, &f)?;
    for numeric in [false, true] {
        let mut changed = base.clone();
        if numeric {
            changed.tracker.min_hits += 1;
        } else {
            changed.class_index = 1;
        }
        let mut other = RtpPackageTracker::new(&r, &f.package, changed, &f.dep, &f.cx, &f.scalar)?;
        assert_ne!(owner.recipe(), other.recipe());
        let frames = collect(&mut other, &f)?;
        assert_eq!(frames.len(), original.len());
        for (a, b) in original.iter().zip(&frames) {
            assert_eq!(a.detected().digest(), b.detected().digest());
            assert_eq!(a.detected().receipt(), b.detected().receipt());
            assert_ne!(a.digest(), b.digest());
        }
    }
    Ok(())
}

#[test]
fn lifetime_frame_limit_refuses_instead_of_certifying_a_prefix() -> TestResult {
    let f = Fixture::new("lifetime", &real_dump(true))?;
    let r = f.retained(1)?;
    let mut req = request(&r, &f.cx)?;
    req.limits.max_frames = 1;
    let mut owner = RtpPackageTracker::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
    assert!(matches!(
        until_error(&mut owner, &f)?,
        RtpTrackingError::Limit
    ));
    let stats = owner.stats();
    assert_eq!(stats.frames, 1);
    assert_eq!(stats.detection.frames, 2);
    assert_eq!(stats.failures, 1);
    assert!(stats.ended && !stats.complete());
    for _ in 0..3 {
        assert!(matches!(
            owner.step(&f.dep, &f.cx, &f.scalar)?,
            RtpTrackingStep::Ended(_)
        ));
        assert_eq!(format!("{:?}", owner.stats()), format!("{stats:?}"));
    }
    Ok(())
}

#[test]
fn final_delivery_cancellation_discards_tracks_and_drains_both_owners() -> TestResult {
    let f = Fixture::new("cancel", &real_dump(false))?;
    let r = f.retained(1)?;
    let mut owner = RtpPackageTracker::new(
        &r,
        &f.package,
        request(&r, &f.cx)?,
        &f.dep,
        &f.cx,
        &f.scalar,
    )?;
    f.cx.set_cancel_at_checkpoint("rtp_track:deliver");
    assert!(matches!(
        until_error(&mut owner, &f)?,
        RtpTrackingError::Cancelled
    ));
    assert_eq!(owner.stats().frames, 0);
    assert_eq!(owner.stats().detection.frames, 1);
    assert!(f.cx.is_drain_completed() && f.scalar.is_drain_completed());
    assert!(!owner.stats().complete());
    Ok(())
}

#[test]
fn stale_policy_and_lost_custody_never_become_empty_tracking_results() -> TestResult {
    for policy in [false, true] {
        let mut f = Fixture::new("custody", &real_dump(false))?;
        let r = f.retained(1)?;
        let mut owner = RtpPackageTracker::new(
            &r,
            &f.package,
            request(&r, &f.cx)?,
            &f.dep,
            &f.cx,
            &f.scalar,
        )?;
        if policy {
            let p = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [1, 1], &[[0, 0, 1, 1]])?;
            let approval = preview_mask(&f.dep, &p)?.approval;
            declare_mask(&mut f.dep, &p, approval, &f.cx)?;
        } else {
            let chunk = *r.report().chunk_digests().first().ok_or("chunk")?;
            std::fs::remove_file(f.dep.publisher().spool().object_path(chunk))?;
        }
        let e = until_error(&mut owner, &f)?;
        assert!(
            matches!(e, RtpTrackingError::StaleBasis) && policy
                || matches!(e, RtpTrackingError::Detection(_)) && !policy
        );
        assert_eq!(owner.stats().frames, 0);
        assert_eq!(owner.stats().detection.attempts, 0);
        assert!(!owner.stats().complete());
    }
    Ok(())
}

#[test]
fn real_recovery_preserves_source_gaps_and_independent_tracking_allowance() -> TestResult {
    let mut packets = packetize(2, 100, 65534, 7, 90000, 0);
    let missing = packets.iter().position(|p| p.vcl).ok_or("IDR")?;
    packets.remove(missing);
    let f = Fixture::new("gap", &dump_planned(&packets))?;
    let r = f.retained(1)?;
    let req = request(&r, &f.cx)?;
    let mut owner = RtpPackageTracker::new(&r, &f.package, req.clone(), &f.dep, &f.cx, &f.scalar)?;
    let frames = collect(&mut owner, &f)?;
    assert!(!frames.is_empty());
    assert!(
        frames
            .iter()
            .all(|v| v.detected().source().decoder_epoch > 0)
    );
    assert_eq!(
        frames.first().ok_or("recovered frame")?.reset(),
        Some(RtpTrackReset::SourceGap)
    );
    assert!(owner.stats().detection.native.refusals > 0);
    assert!(!owner.stats().complete());
    let mut req = req;
    req.limits.max_frames = 1;
    let mut limited = RtpPackageTracker::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
    assert!(matches!(
        until_error(&mut limited, &f)?,
        RtpTrackingError::Limit
    ));
    assert_eq!(limited.stats().frames, 1);
    assert!(!limited.stats().complete());
    Ok(())
}

#[test]
fn invalid_class_is_refused_before_source_readback() -> TestResult {
    let f = Fixture::new("invalid-class", &real_dump(false))?;
    let r = f.retained(1)?;
    let mut req = request(&r, &f.cx)?;
    req.class_index = f.package.spec().labels.len();
    let chunk = *r.report().chunk_digests().first().ok_or("chunk")?;
    std::fs::remove_file(f.dep.publisher().spool().object_path(chunk))?;
    assert!(matches!(
        RtpPackageTracker::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar),
        Err(RtpTrackingError::InvalidRequest)
    ));
    Ok(())
}

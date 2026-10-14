#![forbid(unsafe_code)]
//! Actual retained RTP decoding and the committed neural package, not caller-supplied boxes.
mod rtpdump_support;

#[path = "rtpdump_detection_contract/cascade.rs"]
mod cascade;

use fss_core::{ContentDigest, SensorId, StreamId, TimestampNs};
use fss_reference::ingest::privacy_mask::{
    MASK_FILL_RGB, PrivacyMaskPolicy, declare_mask, preview_mask,
};
use fss_reference::ingest::recorded_decode::video_rgb::{i420_to_rgb, video_rgb_receipt};
use fss_reference::ingest::rgb_detections::{RgbDetectionBudget, project_rgb_detections};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::rtpdump::detect::*;
use fss_reference::ingest::rtpdump::import::{
    RtpImportLimits, RtpImportScope, prepare_rtp_import, publish_rtp_import,
};
use fss_reference::ingest::rtpdump::recovery::checked_decode::receipt::ReceiptedRtpDecodeStep;
use fss_reference::ingest::rtpdump::recovery::decode::RetainedRtpDecodeRequest;
use fss_reference::ingest::rtpdump::recovery::{
    RecoveredRtpImport, RtpRecoveryPolicy, inspect_rtp_import,
};
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};
use rtpdump_support::*;
use std::path::PathBuf;

const PACKAGE: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");
const PACKAGE_SHA: &str = "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";
const SITE: &str = "site:rtp-neural";
const SENSOR: &str = "sensor:rtp-neural";

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
                "rtp-neural-{label}-{}-{attempt}",
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
                            stream: StreamId::parse("stream:rtp-neural")?,
                            receive_time: TimestampNs(1_000_000_000),
                        },
                        config_for(7),
                        RtpImportLimits::default(),
                        &cx,
                    )?;
                    let root = publish_rtp_import(plan, &cx, &mut dep)?.root();
                    drop(dep);
                    // No original input path exists; every test uses cold retained custody.
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
    fn mask(&mut self, dimensions: [u32; 2]) -> TestResult {
        let p = PrivacyMaskPolicy::new(
            SensorId::parse(SENSOR)?,
            dimensions,
            &[[0, 0, dimensions[0], dimensions[1]]],
        )?;
        let approval = preview_mask(&self.dep, &p)?.approval;
        declare_mask(&mut self.dep, &p, approval, &self.cx)?;
        Ok(())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
fn request(retained: &RecoveredRtpImport, cx: &ReplayCx) -> Result<RtpDetectionRequest, Error> {
    let pair = retained
        .h264_parameters(cx)?
        .unique_pair()
        .ok_or("parameters")?;
    Ok(RtpDetectionRequest::new(RetainedRtpDecodeRequest::new(
        pair,
    )))
}
fn collect(
    detector: &mut RtpPackageDetector<'_>,
    f: &Fixture,
) -> Result<Vec<RtpDetectedFrame>, Error> {
    let mut frames = Vec::new();
    for _ in 0..20_000 {
        match detector.step(&f.dep, &f.cx, &f.scalar)? {
            RtpDetectionStep::Frame(frame) => frames.push(frame),
            RtpDetectionStep::Ended(stats) => {
                assert_eq!(stats.frames, frames.len());
                return Ok(frames);
            }
            _ => {}
        }
    }
    Err("fixture progress bound".into())
}
fn until_error(
    detector: &mut RtpPackageDetector<'_>,
    f: &Fixture,
) -> Result<RtpDetectionError, Error> {
    for _ in 0..20_000 {
        match detector.step(&f.dep, &f.cx, &f.scalar) {
            Err(e) => return Ok(e),
            Ok(RtpDetectionStep::Ended(_)) => return Err("expected a terminal refusal".into()),
            _ => {}
        }
    }
    Err("fixture progress bound".into())
}

#[test]
fn cold_rtp_uses_real_color_neural_execution_and_exact_native_receipts() -> TestResult {
    let f = Fixture::new("color", &real_dump(true))?;
    let retained = f.retained(991)?;
    let req = request(&retained, &f.cx)?;
    let before = f.dep.current_anchor().clone();
    let mut detector =
        RtpPackageDetector::new(&retained, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
    let frames = collect(&mut detector, &f)?;
    assert!(detector.stats().complete());
    assert_eq!(frames.len(), 4);
    assert_eq!(detector.stats().attempts, 4);
    assert!(detector.stats().execution_macs > 0 && detector.stats().tensor_bytes > 0);
    assert_eq!(*f.dep.current_anchor(), before);
    let mut native =
        retained.decode_h264_receipted(req.decode, req.custody, req.receipts, &f.dep, &f.cx)?;
    let mut at = 0;
    for _ in 0..20_000 {
        match native.step(&f.dep, &f.cx)? {
            ReceiptedRtpDecodeStep::Frame { frame, receipt } => {
                let actual = &frames[at];
                assert_eq!(actual.receipt(), &receipt);
                assert_eq!(actual.source().output_index, at);
                assert_eq!(actual.source().root, f.root);
                assert_eq!(actual.source().sensor.as_str(), SENSOR);
                assert_eq!(actual.source().capture.latest, TimestampNs(1_000_000_000));
                assert_eq!(
                    actual.inference().source().exposure,
                    receipt.digest().bytes()
                );
                assert_eq!(
                    actual.inference().source().encoded_sha256,
                    retained.report().input_digest().bytes()
                );
                let rgb = i420_to_rgb(frame.pixels(), frame.cb(), frame.cr(), frame.dimensions())?;
                let decoded = video_rgb_receipt(
                    frame.source().recording.bytes(),
                    receipt.digest(),
                    receipt.plane_digests()[3],
                    frame.dimensions(),
                    &rgb,
                );
                let allowed = frame.mask().allowed(frame.dimensions())?;
                let expected = f.package.model().run_rgb_pixels(
                    &rgb,
                    decoded,
                    actual.inference().source(),
                    &allowed,
                    req.analysis.run,
                    &f.scalar,
                )?;
                let projected = project_rgb_detections(
                    &expected,
                    f.package.contract(),
                    &allowed,
                    &mut RgbDetectionBudget::new(2_000_000_000, 256 * 1024 * 1024),
                    &f.scalar,
                )?;
                assert_eq!(actual.inference().identity(), expected.identity());
                assert_eq!(actual.inference().output_digest(), expected.output_digest());
                assert_eq!(actual.detections().digest(), projected.digest());
                at += 1;
            }
            ReceiptedRtpDecodeStep::Ended(_) => break,
            _ => {}
        }
    }
    assert_eq!(at, 4);
    Ok(())
}

#[test]
fn fresh_ingress_reproduces_every_coupled_detection_identity() -> TestResult {
    let f = Fixture::new("reproduce", &real_dump(false))?;
    let mut runs = Vec::new();
    for ingress in [1, 999] {
        let r = f.retained(ingress)?;
        let mut d = RtpPackageDetector::new(
            &r,
            &f.package,
            request(&r, &f.cx)?,
            &f.dep,
            &f.cx,
            &f.scalar,
        )?;
        runs.push(
            collect(&mut d, &f)?
                .iter()
                .map(RtpDetectedFrame::digest)
                .collect::<Vec<_>>(),
        );
        assert!(d.stats().complete());
    }
    assert_eq!(runs[0], runs[1]);
    Ok(())
}

#[test]
fn masks_apply_to_color_before_inference_and_reject_every_private_detection() -> TestResult {
    let mut f = Fixture::new("masked", &real_dump(false))?;
    let r = f.retained(1)?;
    let req = request(&r, &f.cx)?;
    let mut native = r.decode_h264(req.decode, &f.dep, &f.cx)?;
    let mut dimensions = None;
    for _ in 0..20_000 {
        if let fss_reference::ingest::rtpdump::recovery::decode::RetainedRtpDecodeStep::Frame(
            frame,
        ) = native.step(&f.dep, &f.cx)?
        {
            dimensions = Some(frame.dimensions());
            break;
        }
    }
    let dimensions = dimensions.ok_or("native dimensions missing")?;
    drop(native);
    f.mask(dimensions)?;
    let r = f.retained(2)?;
    let mut d = RtpPackageDetector::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
    let frames = collect(&mut d, &f)?;
    assert!(d.stats().complete());
    for frame in frames {
        assert!(frame.source().policy.is_some());
        assert!(frame.detections().detections().is_empty());
        assert_eq!(
            frame.inference().decode_receipt().rgb_sha256,
            ContentDigest::sha256(&MASK_FILL_RGB.repeat((dimensions[0] * dimensions[1]) as usize))
                .bytes()
        );
        assert_eq!(
            frame.inference().source().permission_mask,
            ContentDigest::sha256(&vec![0; (dimensions[0] * dimensions[1]) as usize]).bytes()
        );
    }
    Ok(())
}

#[test]
fn explicit_threshold_changes_detection_recipe_not_native_frame_identity() -> TestResult {
    let f = Fixture::new("threshold", &real_dump(false))?;
    let r = f.retained(1)?;
    let mut result = Vec::new();
    for threshold in [None, Some(1_000_000)] {
        let mut req = request(&r, &f.cx)?;
        req.minimum_score_ppm = threshold;
        let mut d = RtpPackageDetector::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
        result.push(collect(&mut d, &f)?);
    }
    for (a, b) in result[0].iter().zip(&result[1]) {
        assert_eq!(a.receipt(), b.receipt());
        assert_eq!(a.inference().output_digest(), b.inference().output_digest());
        assert_ne!(a.recipe(), b.recipe());
        assert_ne!(a.digest(), b.digest());
    }
    Ok(())
}

#[test]
fn lifetime_frame_color_and_execution_limits_cannot_certify_a_shorter_prefix() -> TestResult {
    let f = Fixture::new("limits", &real_dump(false))?;
    let r = f.retained(1)?;
    for kind in ["frames", "execution"] {
        let mut req = request(&r, &f.cx)?;
        if kind == "frames" {
            req.analysis.max_frames = 1;
        } else {
            req.analysis.max_execution_macs = req.analysis.run.execution.max_macs;
        }
        let mut d = RtpPackageDetector::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
        assert!(matches!(
            until_error(&mut d, &f)?,
            RtpDetectionError::Limit(_)
        ));
        assert_eq!(d.stats().frames, 1);
        assert_eq!(d.stats().attempts, 1);
        assert!(d.stats().ended && !d.stats().complete());
        let before = d.stats();
        assert!(matches!(
            d.step(&f.dep, &f.cx, &f.scalar)?,
            RtpDetectionStep::Ended(_)
        ));
        assert_eq!(d.stats(), before);
    }
    let mut req = request(&r, &f.cx)?;
    req.analysis.max_color_pixels = 0;
    let mut d = RtpPackageDetector::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
    assert!(matches!(
        until_error(&mut d, &f)?,
        RtpDetectionError::Limit("color_pixels")
    ));
    assert_eq!(d.stats().attempts, 0);
    Ok(())
}

#[test]
fn failed_native_execution_keeps_its_work_reservation_and_no_result() -> TestResult {
    let f = Fixture::new("neural-refusal", &real_dump(false))?;
    let r = f.retained(1)?;
    let mut req = request(&r, &f.cx)?;
    req.analysis.run.execution.max_macs = 1;
    let mut d = RtpPackageDetector::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
    assert!(matches!(
        until_error(&mut d, &f)?,
        RtpDetectionError::Inference(_)
    ));
    let s = d.stats();
    assert_eq!(s.frames, 0);
    assert_eq!(s.native.frames, 1);
    assert_eq!(s.attempts, 1);
    assert_eq!(s.preprocess_work, req.analysis.run.preprocess.max_macs);
    assert_eq!(s.execution_macs, 1);
    assert_eq!(s.tensor_bytes, req.analysis.run.execution.max_bytes as u64);
    assert!(!s.complete());
    Ok(())
}

#[test]
fn postprocessing_and_receipt_failures_are_not_empty_detections() -> TestResult {
    let f = Fixture::new("stage-refusal", &real_dump(false))?;
    let r = f.retained(1)?;
    for native in [false, true] {
        let mut req = request(&r, &f.cx)?;
        if native {
            req.receipts.max_receipt_bytes = 1;
        } else {
            req.analysis.detection_work = 0;
        }
        let mut d = RtpPackageDetector::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
        let error = until_error(&mut d, &f)?;
        assert!(
            matches!(error, RtpDetectionError::Detection(_)) && !native
                || matches!(error, RtpDetectionError::Source(_)) && native
        );
        assert_eq!(d.stats().frames, 0);
        assert_eq!(d.stats().attempts, usize::from(!native));
        assert!(d.stats().ended && !d.stats().complete());
    }
    Ok(())
}

#[test]
fn cancellation_at_inference_and_final_delivery_never_discloses_a_partial_result() -> TestResult {
    for stage in ["rtp_detect:inference", "rtp_detect:deliver"] {
        let f = Fixture::new("cancel", &real_dump(false))?;
        let r = f.retained(1)?;
        let mut d = RtpPackageDetector::new(
            &r,
            &f.package,
            request(&r, &f.cx)?,
            &f.dep,
            &f.cx,
            &f.scalar,
        )?;
        f.cx.set_cancel_at_checkpoint(stage);
        assert!(matches!(
            until_error(&mut d, &f)?,
            RtpDetectionError::Cancelled
        ));
        assert_eq!(d.stats().frames, 0);
        assert_eq!(d.stats().attempts, 1);
        assert!(f.cx.is_drain_completed() && f.scalar.is_drain_completed());
        assert!(!d.stats().complete());
    }
    Ok(())
}

#[test]
fn scalar_cancellation_also_terminates_the_source_owner() -> TestResult {
    let f = Fixture::new("scalar-cancel", &real_dump(false))?;
    let r = f.retained(1)?;
    let mut d = RtpPackageDetector::new(
        &r,
        &f.package,
        request(&r, &f.cx)?,
        &f.dep,
        &f.cx,
        &f.scalar,
    )?;
    f.scalar.request_cancellation();
    assert!(matches!(
        d.step(&f.dep, &f.cx, &f.scalar),
        Err(RtpDetectionError::Cancelled)
    ));
    assert_eq!(d.stats().attempts, 0);
    assert!(f.cx.is_drain_completed() && f.scalar.is_drain_completed());
    Ok(())
}

#[test]
fn lost_original_custody_and_changed_policy_fence_pending_neural_work() -> TestResult {
    for policy in [false, true] {
        let mut f = Fixture::new("custody", &real_dump(false))?;
        let r = f.retained(1)?;
        let mut d = RtpPackageDetector::new(
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
        let e = until_error(&mut d, &f)?;
        assert!(
            matches!(e, RtpDetectionError::StaleBasis) && policy
                || matches!(e, RtpDetectionError::Source(_)) && !policy
        );
        assert_eq!(d.stats().attempts, 0);
        assert_eq!(d.stats().frames, 0);
    }
    Ok(())
}

#[test]
fn recovered_frames_preserve_gap_history_and_cannot_refill_inference_allowance() -> TestResult {
    let mut packets = packetize(2, 100, 65534, 7, 90000, 0);
    let missing = packets.iter().position(|p| p.vcl).ok_or("IDR")?;
    packets.remove(missing);
    let f = Fixture::new("recovered", &dump_planned(&packets))?;
    let r = f.retained(1)?;
    let req = request(&r, &f.cx)?;
    let mut d = RtpPackageDetector::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
    let frames = collect(&mut d, &f)?;
    assert!(!frames.is_empty());
    assert!(frames.iter().all(|frame| frame.source().decoder_epoch > 0));
    assert!(d.stats().native.refusals > 0 && d.stats().native.skipped_groups > 0);
    assert!(!d.stats().complete());
    let mut req = req;
    req.analysis.max_frames = 1;
    let mut d = RtpPackageDetector::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
    assert!(matches!(
        until_error(&mut d, &f)?,
        RtpDetectionError::Limit("inference_frames")
    ));
    assert_eq!(d.stats().attempts, 1);
    assert_eq!(d.stats().frames, 1);
    assert!(!d.stats().complete());
    Ok(())
}

#[test]
fn malformed_tail_and_invalid_admission_never_claim_a_complete_quiet_scan() -> TestResult {
    let mut bytes = real_dump(false);
    bytes.extend_from_slice(&[0, 10, 0]);
    let f = Fixture::new("tail", &bytes)?;
    let r = f.retained(1)?;
    let req = request(&r, &f.cx)?;
    let mut d = RtpPackageDetector::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
    collect(&mut d, &f)?;
    assert!(d.stats().ended && !d.stats().complete());
    assert!(d.stats().native.refusals > 0);
    let mut bad = req;
    bad.analysis.max_frames = 0;
    assert!(matches!(
        RtpPackageDetector::new(&r, &f.package, bad, &f.dep, &f.cx, &f.scalar),
        Err(RtpDetectionError::InvalidRequest)
    ));
    bad = req;
    bad.minimum_score_ppm = Some(1_000_001);
    assert!(matches!(
        RtpPackageDetector::new(&r, &f.package, bad, &f.dep, &f.cx, &f.scalar),
        Err(RtpDetectionError::Package(_))
    ));
    Ok(())
}

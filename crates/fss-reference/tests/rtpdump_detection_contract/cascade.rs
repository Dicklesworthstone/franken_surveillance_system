#![forbid(unsafe_code)]
//! Reuse the actual retained-RTP and committed YOLOX fixture, not invented frame receipts.
use super::*;
use fss_reference::ingest::activity::{ActivityPolicy, SamplingReason};
use fss_reference::ingest::pixel_change::{PixelChangeConfig, PixelChangeReset};
use fss_reference::ingest::rtpdump::detect::cascade::*;

fn quiet(stride: u32, hold: u32) -> ActivityPolicy {
    ActivityPolicy {
        change: PixelChangeConfig {
            minimum_delta: 255,
            minimum_changed_pixels: 4_194_304,
            minimum_changed_fraction_ppm: 1_000_000,
        },
        sentinel_stride: stride,
        post_activity_frames: hold,
    }
}
fn cascade_request(r: &RecoveredRtpImport, f: &Fixture, stride: u32) -> Result<RtpCascadeRequest, Error> {
    Ok(RtpCascadeRequest::new(request(r, &f.cx)?, quiet(stride, 0), 64_000_000))
}
fn cascade_collect(d: &mut RtpDetectionCascade<'_>, f: &Fixture) -> Result<Vec<RtpCascadeFrame>, Error> {
    let mut frames = Vec::new();
    for _ in 0..20_000 {
        match d.step(&f.dep, &f.cx, &f.scalar)? {
            RtpCascadeStep::Frame(frame) => frames.push(frame),
            RtpCascadeStep::Ended(stats) => {
                assert_eq!(stats.delivered, frames.len());
                return Ok(frames);
            }
            RtpCascadeStep::Progress { .. } => {}
        }
    }
    Err("cascade fixture progress bound".into())
}
fn cascade_error(d: &mut RtpDetectionCascade<'_>, f: &Fixture) -> Result<RtpDetectionError, Error> {
    for _ in 0..20_000 {
        match d.step(&f.dep, &f.cx, &f.scalar) {
            Err(e) => return Ok(e),
            Ok(RtpCascadeStep::Ended(_)) => return Err("expected cascade refusal".into()),
            _ => {}
        }
    }
    Err("cascade fixture progress bound".into())
}

#[test]
fn stride_one_preserves_every_native_receipt_and_numerical_detection_identity() -> TestResult {
    let f = Fixture::new("cascade-exhaustive", &real_dump(true))?;
    let r = f.retained(77)?;
    let req = request(&r, &f.cx)?;
    let mut exhaustive = RtpPackageDetector::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
    let expected = collect(&mut exhaustive, &f)?;
    let mut sampled = RtpDetectionCascade::new(
        &r, &f.package, cascade_request(&r, &f, 1)?, &f.dep, &f.cx, &f.scalar,
    )?;
    let frames = cascade_collect(&mut sampled, &f)?;
    assert_eq!(frames.len(), expected.len());
    for (index, (frame, original)) in frames.iter().zip(&expected).enumerate() {
        let inferred = frame.detection().ok_or("all frames selected")?;
        assert_eq!(inferred.digest(), original.digest());
        assert_eq!(frame.receipt(), original.receipt());
        assert_eq!(inferred.source().output_index, index);
        assert!(frame.decision().reasons().contains(&SamplingReason::Sentinel));
        assert_eq!(frame.decision().predecessor(), index.checked_sub(1).map(|i| frames[i].digest()));
        assert_eq!(ContentDigest::sha256(frame.decision().bytes()), frame.decision().digest());
    }
    assert!(sampled.stats().complete() && sampled.stats().exhaustive());
    assert_eq!(sampled.stats().detection, exhaustive.stats());
    Ok(())
}

#[test]
fn quiet_skips_save_neural_work_but_keep_real_display_indices_and_source_receipts() -> TestResult {
    let f = Fixture::new("cascade-skip", &real_dump(false))?;
    let r = f.retained(1)?;
    let req = request(&r, &f.cx)?;
    let mut exhaustive = RtpPackageDetector::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
    let expected = collect(&mut exhaustive, &f)?;
    let mut sampled = RtpDetectionCascade::new(
        &r, &f.package, cascade_request(&r, &f, 2)?, &f.dep, &f.cx, &f.scalar,
    )?;
    let before = f.dep.current_anchor().clone();
    let frames = cascade_collect(&mut sampled, &f)?;
    assert_eq!(frames.len(), 4);
    for (index, frame) in frames.iter().enumerate() {
        assert_eq!(frame.receipt(), expected[index].receipt());
        assert_eq!(frame.decision().observation().output_index, index as u64);
        assert_eq!(frame.decision().selected(), index % 2 == 0);
        assert_eq!(frame.decision().predecessor(), index.checked_sub(1).map(|i| frames[i].digest()));
        if let Some(detection) = frame.detection() {
            assert_eq!(detection.source().output_index, index);
            assert_eq!(detection.digest(), expected[index].digest());
        } else {
            assert!(frame.decision().reasons().is_empty());
            let measurement = frame.decision().observation().statistics.as_ref().ok_or("measured skip")?;
            assert!(!measurement.candidate);
            assert!(frame.decision().comparison_unavailable().is_none());
        }
    }
    let s = sampled.stats();
    assert!(s.complete() && !s.exhaustive() && !s.detection.complete());
    assert_eq!((s.selected, s.skipped, s.detection.attempts), (2, 2, 2));
    assert_eq!(s.detection.native, exhaustive.stats().native);
    assert_eq!(s.detection.custody_read_bytes, exhaustive.stats().custody_read_bytes);
    assert!(s.detection.execution_macs < exhaustive.stats().execution_macs);
    assert!(s.detection.color_pixels < exhaustive.stats().color_pixels);
    assert_eq!(*f.dep.current_anchor(), before);
    Ok(())
}

#[test]
fn zero_comparison_work_forces_inference_and_never_refills_its_allowance() -> TestResult {
    let f = Fixture::new("cascade-work-floor", &real_dump(false))?;
    let r = f.retained(1)?;
    let mut req = cascade_request(&r, &f, 256)?;
    req.max_comparisons = 0;
    let mut d = RtpDetectionCascade::new(&r, &f.package, req.clone(), &f.dep, &f.cx, &f.scalar)?;
    let frames = cascade_collect(&mut d, &f)?;
    assert_eq!(frames.len(), 4);
    for frame in &frames[1..] {
        assert!(frame.detection().is_some());
        assert_eq!(frame.decision().comparison_unavailable(), Some(RtpComparisonUnavailable::WorkBudget));
        assert!(frame.decision().observation().statistics.is_none());
        assert!(frame.decision().reasons().contains(&SamplingReason::ComparisonBudgetFloor));
    }
    assert_eq!(d.stats().comparisons, 0);
    assert_eq!(d.stats().comparison_fallbacks, 3);
    assert!(d.stats().exhaustive());
    req.detection.analysis.max_frames = 2;
    let mut d = RtpDetectionCascade::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
    assert!(matches!(cascade_error(&mut d, &f)?, RtpDetectionError::Limit("inference_frames")));
    assert_eq!(d.stats().detection.attempts, 2);
    assert_eq!(d.stats().delivered, 2);
    assert!(!d.stats().complete());
    let frozen = d.stats();
    assert!(matches!(d.step(&f.dep, &f.cx, &f.scalar)?, RtpCascadeStep::Ended(_)));
    assert_eq!(d.stats(), frozen);
    Ok(())
}

#[test]
fn baseline_memory_floor_is_explicit_and_selects_every_frame_without_comparison() -> TestResult {
    let f = Fixture::new("cascade-memory-floor", &real_dump(false))?;
    let r = f.retained(1)?;
    let mut req = cascade_request(&r, &f, 256)?;
    req.max_baseline_bytes = 0;
    let mut d = RtpDetectionCascade::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
    for frame in cascade_collect(&mut d, &f)? {
        assert!(frame.detection().is_some());
        assert_eq!(frame.decision().comparison_unavailable(), Some(RtpComparisonUnavailable::BaselineLimit));
    }
    assert_eq!(d.stats().comparisons, 0);
    assert_eq!(d.stats().comparison_fallbacks, 4);
    assert!(d.stats().exhaustive());
    Ok(())
}

#[test]
fn initial_comparison_reset_selects_its_whole_followup_burst() -> TestResult {
    let f = Fixture::new("cascade-hold", &real_dump(false))?;
    let r = f.retained(1)?;
    let mut req = cascade_request(&r, &f, 256)?;
    req.policy.post_activity_frames = 2;
    let mut d = RtpDetectionCascade::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
    let frames = cascade_collect(&mut d, &f)?;
    assert_eq!(frames.iter().map(|f| f.decision().selected()).collect::<Vec<_>>(), [true, true, true, false]);
    for frame in &frames[1..3] {
        assert!(frame.decision().reasons().contains(&SamplingReason::ActivityHold));
        assert!(!frame.decision().reasons().contains(&SamplingReason::Sentinel));
    }
    assert!(d.stats().complete());
    Ok(())
}

#[test]
fn required_frames_bind_the_recipe_and_cannot_be_skipped_or_fabricated() -> TestResult {
    let f = Fixture::new("cascade-required", &real_dump(false))?;
    let r = f.retained(1)?;
    let reason = ContentDigest::sha256(b"owner-selected-evidence-window");
    let mut req = cascade_request(&r, &f, 256)?;
    req.required_frames = vec![(3, reason), (1, reason)];
    let mut d = RtpDetectionCascade::new(&r, &f.package, req.clone(), &f.dep, &f.cx, &f.scalar)?;
    let recipe = d.recipe();
    let frames = cascade_collect(&mut d, &f)?;
    assert_eq!(frames.iter().map(|f| f.decision().selected()).collect::<Vec<_>>(), [true, true, false, true]);
    for index in [1, 3] {
        assert_eq!(frames[index].decision().required_basis(), Some(reason));
        assert!(frames[index].decision().reasons().contains(&SamplingReason::Required));
    }
    assert!(d.stats().complete());
    req.required_frames.reverse();
    let reordered = RtpDetectionCascade::new(&r, &f.package, req.clone(), &f.dep, &f.cx, &f.scalar)?;
    assert_eq!(reordered.recipe(), recipe);
    req.required_frames.push((100, reason));
    let mut d = RtpDetectionCascade::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
    assert_ne!(d.recipe(), recipe);
    assert_eq!(cascade_collect(&mut d, &f)?.len(), 4);
    assert_eq!(d.stats().unobserved_required, 1);
    assert!(!d.stats().complete());
    Ok(())
}

#[test]
fn fresh_ingress_reproduces_every_sampling_byte_and_coupled_result() -> TestResult {
    let f = Fixture::new("cascade-replay", &real_dump(true))?;
    let mut runs = Vec::new();
    for ingress in [1, 991] {
        let r = f.retained(ingress)?;
        let mut d = RtpDetectionCascade::new(&r, &f.package, cascade_request(&r, &f, 2)?, &f.dep, &f.cx, &f.scalar)?;
        runs.push(cascade_collect(&mut d, &f)?.iter()
            .map(|f| (f.digest(), f.decision().bytes().to_vec())).collect::<Vec<_>>());
        assert!(d.stats().complete());
    }
    assert_eq!(runs[0], runs[1]);
    Ok(())
}

#[test]
fn decision_exhaustion_stops_before_comparison_or_neural_admission_not_with_prefix_success() -> TestResult {
    let f = Fixture::new("cascade-decision-budget", &real_dump(false))?;
    let r = f.retained(1)?;
    let mut req = cascade_request(&r, &f, 2)?;
    req.max_decision_bytes = 4096;
    let mut d = RtpDetectionCascade::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
    assert!(matches!(cascade_error(&mut d, &f)?, RtpDetectionError::Limit("sampling_decisions")));
    assert_eq!(d.stats().considered, 1);
    assert_eq!(d.stats().delivered, 1);
    assert_eq!(d.stats().comparisons, 0);
    assert_eq!(d.stats().detection.attempts, 1);
    assert!(!d.stats().complete());
    Ok(())
}

#[test]
fn cancellation_at_gate_comparison_or_delivery_retires_both_owners() -> TestResult {
    for stage in ["rtp_cascade:admit", "rtp_cascade:row", "rtp_cascade:deliver"] {
        let f = Fixture::new("cascade-cancel", &real_dump(false))?;
        let r = f.retained(1)?;
        let mut d = RtpDetectionCascade::new(&r, &f.package, cascade_request(&r, &f, 2)?, &f.dep, &f.cx, &f.scalar)?;
        f.cx.set_cancel_at_checkpoint(stage);
        assert!(matches!(cascade_error(&mut d, &f)?, RtpDetectionError::Cancelled));
        assert!(f.cx.is_drain_completed() && f.scalar.is_drain_completed());
        assert_eq!(d.stats().delivered, usize::from(stage == "rtp_cascade:row"));
        assert!(!d.stats().complete());
        let frozen = d.stats();
        assert!(matches!(d.step(&f.dep, &f.cx, &f.scalar)?, RtpCascadeStep::Ended(_)));
        assert_eq!(d.stats(), frozen);
    }
    Ok(())
}

#[test]
fn quiet_sampling_never_bypasses_current_custody_or_privacy_revalidation() -> TestResult {
    for policy in [false, true] {
        let mut f = Fixture::new("cascade-custody", &real_dump(false))?;
        let r = f.retained(1)?;
        let mut d = RtpDetectionCascade::new(&r, &f.package, cascade_request(&r, &f, 256)?, &f.dep, &f.cx, &f.scalar)?;
        let mut first = false;
        for _ in 0..20_000 {
            if matches!(d.step(&f.dep, &f.cx, &f.scalar)?, RtpCascadeStep::Frame(_)) {
                first = true;
                break;
            }
        }
        assert!(first);
        if policy {
            let p = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [1, 1], &[[0, 0, 1, 1]])?;
            let approval = preview_mask(&f.dep, &p)?.approval;
            declare_mask(&mut f.dep, &p, approval, &f.cx)?;
        } else {
            let chunk = *r.report().chunk_digests().first().ok_or("chunk")?;
            std::fs::remove_file(f.dep.publisher().spool().object_path(chunk))?;
        }
        let e = cascade_error(&mut d, &f)?;
        assert!(matches!(e, RtpDetectionError::StaleBasis) && policy
            || matches!(e, RtpDetectionError::Source(_)) && !policy);
        assert_eq!(d.stats().delivered, 1);
        assert_eq!(d.stats().skipped, 0);
        assert!(!d.stats().complete());
    }
    Ok(())
}

#[test]
fn real_idr_recovery_is_an_unmeasured_inference_floor_and_keeps_gap_accounting() -> TestResult {
    let mut packets = packetize(2, 100, 65534, 7, 90000, 0);
    let missing = packets.iter().position(|p| p.vcl).ok_or("IDR")?;
    packets.remove(missing);
    let f = Fixture::new("cascade-gap", &dump_planned(&packets))?;
    let r = f.retained(1)?;
    let mut req = cascade_request(&r, &f, 256)?;
    req.max_comparisons = 0;
    let mut d = RtpDetectionCascade::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
    let frames = cascade_collect(&mut d, &f)?;
    let first = frames.first().ok_or("recovered native frame")?;
    assert!(first.decision().observation().reset_reasons.contains(&PixelChangeReset::SourceGap));
    assert!(first.decision().observation().statistics.is_none());
    assert!(first.detection().is_some());
    assert!(d.stats().detection.native.refusals > 0);
    assert!(d.stats().detection.native.skipped_groups > 0);
    assert!(!d.stats().complete());
    assert_eq!(d.stats().comparisons, 0);
    Ok(())
}

#[test]
fn malformed_sampling_requests_refuse_before_source_reads() -> TestResult {
    let f = Fixture::new("cascade-invalid", &real_dump(false))?;
    let r = f.retained(1)?;
    let base = cascade_request(&r, &f, 2)?;
    let chunk = *r.report().chunk_digests().first().ok_or("chunk")?;
    std::fs::remove_file(f.dep.publisher().spool().object_path(chunk))?;
    for bad in 0..4 {
        let mut req = base.clone();
        match bad {
            0 => req.policy.sentinel_stride = 0,
            1 => req.max_baseline_bytes = 4_194_305,
            2 => req.max_decision_bytes = 4095,
            _ => req.required_frames = vec![(1, ContentDigest::sha256(b"a")), (1, ContentDigest::sha256(b"b"))],
        }
        assert!(matches!(RtpDetectionCascade::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar), Err(RtpDetectionError::InvalidRequest)));
    }
    Ok(())
}

#[test]
fn cascade_measurements_match_the_existing_native_motion_owner_exactly() -> TestResult {
    use fss_reference::ingest::pixel_change::rtp::{RtpMotionAnalyzer, RtpMotionRequest, RtpMotionStep};
    let f = Fixture::new("cascade-motion-oracle", &real_dump(true))?;
    let r = f.retained(17)?;
    let mut req = cascade_request(&r, &f, 256)?;
    req.policy.change = PixelChangeConfig {
        minimum_delta: 1,
        minimum_changed_pixels: 1,
        minimum_changed_fraction_ppm: 0,
    };
    req.policy.post_activity_frames = 1;
    let mut motion_request = RtpMotionRequest::new(req.detection.decode, req.policy.change, req.max_comparisons);
    motion_request.custody = req.detection.custody;
    motion_request.receipts = req.detection.receipts;
    let mut motion = RtpMotionAnalyzer::open(&r, motion_request, &f.dep, &f.cx)?;
    let mut expected = Vec::new();
    for _ in 0..20_000 {
        match motion.step(&f.dep, &f.cx)? {
            RtpMotionStep::Observation(observation) => expected.push(observation),
            RtpMotionStep::Ended(_) => break,
            RtpMotionStep::Progress { .. } => {}
        }
    }
    assert!(motion.stats().complete());
    let mut cascade = RtpDetectionCascade::new(&r, &f.package, req.clone(), &f.dep, &f.cx, &f.scalar)?;
    let recipe = cascade.recipe();
    let frames = cascade_collect(&mut cascade, &f)?;
    assert_eq!(frames.len(), expected.len());
    for (frame, observation) in frames.iter().zip(expected) {
        assert_eq!(frame.decision().observation(), &observation);
        let changed = observation.statistics.as_ref().is_some_and(|s| s.candidate);
        assert_eq!(frame.decision().reasons().contains(&SamplingReason::PixelChange), changed);
        if changed {
            assert!(frame.detection().is_some());
        }
    }
    assert_eq!(cascade.stats().comparisons, motion.stats().comparisons);
    assert!(cascade.stats().complete());
    req.detection.analysis.max_frames = 1;
    let smaller = RtpDetectionCascade::new(&r, &f.package, req, &f.dep, &f.cx, &f.scalar)?;
    assert_ne!(smaller.recipe(), recipe);
    Ok(())
}

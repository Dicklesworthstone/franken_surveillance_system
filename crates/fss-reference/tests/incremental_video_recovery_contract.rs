#![forbid(unsafe_code)]
//! Real retained AVC/HEVC -> resumable recovery -> exact one-shot temporal evidence.
//! The loose input is deleted by the fixture immediately after native import.

#[path = "cascade_support/mod.rs"]
mod support;

use fss_core::{ContentDigest, LedgerAnchor, SensorId};
use fss_reference::ReferenceDeployment;
use fss_reference::ingest::FileFormatHint;
use fss_reference::ingest::long_dwell::incremental::{
    DwellRestoreLimits, DwellVideoProgress, PreparedIncrementalDwell, RetainedDwellCheckpoint,
};
use fss_reference::ingest::long_dwell::{LongDwellLimits, LongDwellReport};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchError, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::zone_dwell::DwellPolicy;
use support::{Fixture, SITE, TestResult};

const AVC: &[u8] =
    include_bytes!("../../fss-codec-h264/tests/fixtures/decode/p_qcif_ref3_p4x4.h264");
const HEVC: &[u8] = include_bytes!("../../fss-codec-h265/tests/fixtures/decode/i_qcif_cra.h265");
const HEVC_OPEN_GOP: &[u8] = include_bytes!("../../fss-container/tests/fixtures/hevc_av.mp4");
const TOLERANT: WatchOptions = WatchOptions {
    tolerate_decode_refusals: true,
};
const LUMA_CAPACITY: u64 = 176 * 144;

/// The same established corruption as decode_gap_coverage_contract: keep only 20 bytes of
/// the P slice at source segment 3, then recover at the next copy's IDR (segment 12).
fn damaged_avc(segment: usize, pristine_copies: usize) -> TestResult<Vec<u8>> {
    let mut starts = Vec::new();
    let mut from = 0;
    while let Some(offset) = AVC[from..].windows(3).position(|w| w == [0, 0, 1]) {
        starts.push(from + offset + 3);
        from += offset + 3;
    }
    let slice = *starts.get(segment + 3).ok_or("fixture slice")?;
    let next = *starts.get(segment + 4).ok_or("fixture next slice")?;
    let resume = if AVC[next - 4] == 0 {
        next - 4
    } else {
        next - 3
    };
    let mut bytes = AVC[..slice + 20].to_vec();
    bytes.extend_from_slice(&AVC[resume..]);
    for _ in 0..pristine_copies {
        bytes.extend_from_slice(AVC);
    }
    Ok(bytes)
}

/// The existing native truncated-slice fixture: remove the second half of the final CRA
/// slice. A complete copy then supplies the next admitted IRAP.
fn damaged_hevc() -> TestResult<Vec<u8>> {
    let last = HEVC
        .windows(3)
        .rposition(|w| w == [0, 0, 1])
        .ok_or("fixture final NAL")?;
    let mut bytes = HEVC[..last + (HEVC.len() - last) / 2].to_vec();
    bytes.extend_from_slice(HEVC);
    Ok(bytes)
}

fn limits() -> LongDwellLimits {
    let mut limits = LongDwellLimits::default();
    // Native admission accounts coded capacity, including failed and delayed pictures.
    // These retained QCIF fixtures have exactly this capacity; no display count proxy is used.
    limits.decode.h264_limits.max_width = 176;
    limits.decode.h264_limits.max_height = 144;
    limits.decode.h264_limits.max_macroblocks = 11 * 9;
    limits.decode.h265_limits.max_width = 176;
    limits.decode.h265_limits.max_height = 144;
    limits.decode.h265_limits.max_luma_samples = LUMA_CAPACITY;
    limits
}

fn restore_limits() -> DwellRestoreLimits {
    DwellRestoreLimits {
        maximum_prefix_frames: 65_536,
        execution: limits(),
    }
}

fn rule() -> DwellPolicy {
    DwellPolicy {
        minimum_duration_ns: 90_000_000,
        maximum_sample_gap_ns: 110_000_000,
        minimum_observations: 2,
    }
}

fn plan(import_identity: ContentDigest, segment_count: usize) -> WatchPlan {
    WatchPlan {
        import_identity,
        interpretation: ComponentInterpretation::YCbCr,
        first_segment: 0,
        segment_count,
        zones: vec![WatchZone {
            zone_id: "scene".into(),
            x: 0,
            y: 0,
            width: 176,
            height: 144,
        }],
        detector: WatchDetectorConfig::default(),
        tracker: WatchTrackerConfig::default(),
    }
}

fn prepare(f: &Fixture, plan: &WatchPlan, screened: bool) -> TestResult<PreparedIncrementalDwell> {
    let make = if screened {
        PreparedIncrementalDwell::new_screened
    } else {
        PreparedIncrementalDwell::new
    };
    Ok(make(
        &f.deployment,
        plan.clone(),
        rule(),
        TOLERANT,
        limits(),
        &f.cx,
    )?)
}

fn analyze(f: &Fixture, plan: &WatchPlan, screened: bool) -> TestResult<LongDwellReport> {
    let analyze = if screened {
        LongDwellReport::analyze_screened
    } else {
        LongDwellReport::analyze
    };
    Ok(analyze(
        &f.deployment,
        plan,
        rule(),
        TOLERANT,
        &limits(),
        &f.cx,
    )?)
}

fn snapshot(deployment: &ReferenceDeployment) -> (LedgerAnchor, ContentDigest, usize) {
    (
        deployment.current_anchor().clone(),
        deployment.effects().last_root(),
        deployment.publisher().spool().object_count(),
    )
}

fn same_report(actual: &LongDwellReport, expected: &LongDwellReport) -> TestResult {
    assert_eq!(actual.analysis_digest(), expected.analysis_digest());
    assert_eq!(actual.frames_decoded(), expected.frames_decoded());
    assert_eq!(
        actual.source_chunk_bytes_read(),
        expected.source_chunk_bytes_read()
    );
    assert_eq!(
        actual
            .candidates()
            .iter()
            .map(|candidate| candidate.proposal_digest())
            .collect::<Vec<_>>(),
        expected
            .candidates()
            .iter()
            .map(|candidate| candidate.proposal_digest())
            .collect::<Vec<_>>(),
    );
    assert_eq!(actual.to_json(0, None)?, expected.to_json(0, None)?);
    let json = actual.to_json(0, None)?;
    assert!(json.contains("\"absence_certifiable\":false"));
    assert!(json.contains("\"alert_authorized\":false"));
    Ok(())
}

fn assert_complete(
    video: &DwellVideoProgress,
    count: usize,
    first: usize,
    last: usize,
) -> TestResult {
    let recovery = video.recovery.as_ref().ok_or("recovery accounting")?;
    assert!(video.decoder_drained);
    assert_eq!(video.source_segments_consumed, count);
    assert_eq!(recovery.refused_segments, last - first + 1);
    assert_eq!(recovery.decode_refusals.len(), 1);
    assert_eq!(recovery.decode_refusals[0].first_segment, first);
    assert_eq!(recovery.decode_refusals[0].last_segment, last);
    assert_eq!(
        recovery.continuation_items_processed,
        video.display_frames_processed + recovery.discontinuities
    );
    assert_eq!(
        video.display_frames_processed
            + recovery.refused_segments
            + video.skipped_rasl_segments.len(),
        count
    );
    assert!(recovery.decode_encoded_bytes > 0);
    assert!(
        recovery.decode_coded_luma_capacity
            >= video.display_frames_processed as u64 * LUMA_CAPACITY
    );
    assert!(
        video
            .to_json()
            .contains("\"step_unit\":\"continuation_items\"")
    );
    Ok(())
}

fn hot_slices(bytes: &[u8], format: FileFormatHint, count: usize, gap: [usize; 2]) -> TestResult {
    let mut f = Fixture::new("incremental-recovery-hot")?;
    let identity = f.ingest("sensor:recovery-hot", bytes, format, Some(1_000_000_000))?;
    let plan = plan(identity, count);
    let before = snapshot(&f.deployment);
    let strict = PreparedIncrementalDwell::new(
        &f.deployment,
        plan.clone(),
        rule(),
        WatchOptions::default(),
        limits(),
        &f.cx,
    )?;
    let mut strict = strict.start()?;
    assert!(strict.advance(&f.deployment, count, &f.cx).is_err());
    assert!(!strict.complete());
    assert!(strict.retain(&mut f.deployment, &f.cx).is_err());
    assert_eq!(snapshot(&f.deployment), before);

    for screened in [false, true] {
        let expected = analyze(&f, &plan, screened)?;
        for step in [1, 5, 128] {
            let prepared = prepare(&f, &plan, screened)?;
            let mut running = prepared.start()?;
            let mut gap_only = false;
            let mut previous_frames = 0;
            let mut previous_breaks = 0;
            for _ in 0..count * 2 + 1 {
                if running.complete() {
                    break;
                }
                let work = running.advance(&f.deployment, step, &f.cx)?;
                let video = running.video_progress().ok_or("video progress")?;
                let recovery = video.recovery.as_ref().ok_or("recovery accounting")?;
                assert_eq!(video.display_frames_processed, work.frames_decoded);
                assert_eq!(video.source_segments_consumed, work.source_positions);
                assert!(work.source_positions <= count);
                if step == 1 && recovery.discontinuities > previous_breaks {
                    assert_eq!(work.frames_decoded, previous_frames);
                    gap_only = true;
                }
                if let Some(health) = running.health_work() {
                    assert_eq!(health.frames_screened, work.frames_decoded);
                }
                previous_frames = work.frames_decoded;
                previous_breaks = recovery.discontinuities;
            }
            assert!(running.complete());
            if step == 1 {
                assert!(gap_only, "a refusal must be a separate continuation item");
            }
            assert_complete(
                &running.video_progress().ok_or("terminal progress")?,
                count,
                gap[0],
                gap[1],
            )?;
            let report = running.finish(&f.deployment, &f.cx)?;
            for candidate in report.candidates() {
                assert!(
                    candidate.span().last.position < gap[0]
                        || candidate.span().first.position > gap[1],
                    "dwell bridged a decode gap"
                );
            }
            same_report(&report, &expected)?;
        }
    }
    assert_eq!(snapshot(&f.deployment), before);
    Ok(())
}

#[test]
fn avc_recovers_at_idr_in_any_slice_and_preserves_screening_and_exact_evidence() -> TestResult {
    hot_slices(&damaged_avc(3, 1)?, FileFormatHint::AnnexB, 24, [3, 11])
}

#[test]
fn hevc_recovers_at_irap_in_any_slice_and_preserves_screening_and_exact_evidence() -> TestResult {
    hot_slices(&damaged_hevc()?, FileFormatHint::Hevc, 6, [2, 2])
}

#[test]
fn long_avc_recovery_keeps_state_across_the_interactive_frame_bound() -> TestResult {
    let mut f = Fixture::new("incremental-recovery-long")?;
    let bytes = damaged_avc(3, 11)?;
    let identity = f.ingest(
        "sensor:recovery-long",
        &bytes,
        FileFormatHint::AnnexB,
        Some(1_000_000_000),
    )?;
    let plan = plan(identity, 144);
    let expected = analyze(&f, &plan, false)?;
    let prepared = prepare(&f, &plan, false)?;
    let mut running = prepared.start()?;
    running.advance(&f.deployment, 128, &f.cx)?;
    assert!(!running.complete());
    assert_eq!(running.work().frames_decoded, 127);
    running.advance(&f.deployment, 128, &f.cx)?;
    assert!(running.complete());
    assert_complete(&running.video_progress().ok_or("progress")?, 144, 3, 11)?;
    same_report(&running.finish(&f.deployment, &f.cx)?, &expected)
}

#[test]
fn a_gap_checkpoint_cold_replays_exact_items_and_terminal_retry_is_idempotent() -> TestResult {
    for (bytes, format, count, gap) in [
        (damaged_avc(3, 1)?, FileFormatHint::AnnexB, 24, [3, 11]),
        (damaged_hevc()?, FileFormatHint::Hevc, 6, [2, 2]),
    ] {
        let mut f = Fixture::new("incremental-recovery-cold")?;
        let identity = f.ingest("sensor:recovery-cold", &bytes, format, Some(1_000_000_000))?;
        let plan = plan(identity, count);
        let prepared = prepare(&f, &plan, true)?;
        let mut running = prepared.start()?;
        for _ in 0..count * 2 {
            running.advance(&f.deployment, 1, &f.cx)?;
            if running
                .video_progress()
                .and_then(|video| video.recovery)
                .is_some_and(|recovery| recovery.discontinuities != 0)
            {
                break;
            }
        }
        let video = running.video_progress().ok_or("gap progress")?;
        assert!(!video.decoder_drained);
        assert_eq!(
            video
                .recovery
                .as_ref()
                .ok_or("recovery")?
                .decode_refusals
                .len(),
            1
        );
        let prefix = running.work();
        let health = running.health_work();
        let pin = running.retain(&mut f.deployment, &f.cx)?;
        let retained_state = snapshot(&f.deployment);
        assert_eq!(running.retain(&mut f.deployment, &f.cx)?, pin);
        assert_eq!(snapshot(&f.deployment), retained_state);
        drop(running);
        drop(prepared);
        let root = f.deployment.root().to_path_buf();
        drop(f.deployment);
        let mut deployment = ReferenceDeployment::reopen(&root, SITE, &f.cx)?;
        let saved = RetainedDwellCheckpoint::open(&deployment, pin, &restore_limits(), &f.cx)?;
        assert_eq!(saved.video_progress(), Some(&video));
        assert_eq!(saved.prefix_work(), prefix);
        assert!(!saved.complete());
        let mut resumed = saved.resume(&deployment, &restore_limits(), &f.cx)?;
        assert_eq!(resumed.work(), prefix);
        assert_eq!(resumed.restoration_work(), prefix);
        assert_eq!(resumed.health_work(), health);
        assert_eq!(resumed.restoration_health_work(), health);
        assert_eq!(resumed.video_progress(), Some(video));
        while !resumed.complete() {
            resumed.advance(&deployment, 1, &f.cx)?;
        }
        assert_complete(
            &resumed.video_progress().ok_or("terminal progress")?,
            count,
            gap[0],
            gap[1],
        )?;
        let terminal = resumed.retain(&mut deployment, &f.cx)?;
        let report = resumed.finish(&deployment, &f.cx)?;
        let expected = LongDwellReport::analyze_screened(
            &deployment,
            &plan,
            rule(),
            TOLERANT,
            &limits(),
            &f.cx,
        )?;
        same_report(&report, &expected)?;
        let after = snapshot(&deployment);
        let completed =
            RetainedDwellCheckpoint::open(&deployment, terminal, &restore_limits(), &f.cx)?;
        assert!(completed.complete());
        let retry = completed.resume(&deployment, &restore_limits(), &f.cx)?;
        assert!(retry.complete());
        assert_eq!(retry.retain(&mut deployment, &f.cx)?, terminal);
        same_report(&retry.finish(&deployment, &f.cx)?, &expected)?;
        assert_eq!(snapshot(&deployment), after);
    }
    Ok(())
}

#[test]
fn zero_picture_gap_prefix_is_resumable_but_all_unusable_range_still_refuses() -> TestResult {
    for copies in [0, 1] {
        let mut f = Fixture::new("incremental-recovery-zero-picture")?;
        let bytes = damaged_avc(0, copies)?;
        let identity = f.ingest(
            "sensor:recovery-zero",
            &bytes,
            FileFormatHint::AnnexB,
            Some(1_000_000_000),
        )?;
        let plan = plan(identity, (copies + 1) * 12);
        let prepared = prepare(&f, &plan, false)?;
        let mut running = prepared.start()?;
        running.advance(&f.deployment, 1, &f.cx)?;
        assert_eq!(running.work().frames_decoded, 0);
        assert!(!running.complete());
        let video = running.video_progress().ok_or("gap progress")?;
        let recovery = video.recovery.as_ref().ok_or("recovery")?;
        assert_eq!(recovery.continuation_items_processed, 1);
        assert_eq!(recovery.refused_segments, 12);
        let pin = running.retain(&mut f.deployment, &f.cx)?;
        let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
        let mut resumed = saved.resume(&f.deployment, &restore_limits(), &f.cx)?;
        assert_eq!(resumed.video_progress(), Some(video));
        if copies == 0 {
            let before = snapshot(&f.deployment);
            assert!(resumed.advance(&f.deployment, 1, &f.cx).is_err());
            assert!(!resumed.complete());
            assert!(resumed.retain(&mut f.deployment, &f.cx).is_err());
            assert!(resumed.finish(&f.deployment, &f.cx).is_err());
            assert_eq!(snapshot(&f.deployment), before);
        } else {
            resumed.advance(&f.deployment, 128, &f.cx)?;
            assert!(resumed.complete());
            same_report(
                &resumed.finish(&f.deployment, &f.cx)?,
                &analyze(&f, &plan, false)?,
            )?;
        }
    }
    Ok(())
}

#[test]
fn hevc_cra_rasl_skips_survive_cold_completion_with_no_fabricated_discontinuity() -> TestResult {
    for count in [3, 7] {
        let mut f = Fixture::new("incremental-recovery-rasl")?;
        let identity = f.ingest(
            "sensor:recovery-rasl",
            HEVC_OPEN_GOP,
            FileFormatHint::Mp4Hevc,
            Some(1_000_000_000),
        )?;
        let mut plan = plan(identity, count);
        plan.first_segment = 3;
        plan.zones[0].width = 64;
        plan.zones[0].height = 48;
        let rule = DwellPolicy {
            minimum_duration_ns: 1,
            maximum_sample_gap_ns: 1_000_000_000,
            minimum_observations: 3,
        };
        let prepared =
            PreparedIncrementalDwell::new(&f.deployment, plan, rule, TOLERANT, limits(), &f.cx)?;
        let mut running = prepared.start()?;
        running.advance(&f.deployment, 1, &f.cx)?;
        let prefix = running.work();
        let pin = running.retain(&mut f.deployment, &f.cx)?;
        let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
        let mut resumed = saved.resume(&f.deployment, &restore_limits(), &f.cx)?;
        assert_eq!(resumed.work(), prefix);
        while !resumed.complete() {
            resumed.advance(&f.deployment, 1, &f.cx)?;
        }
        let video = resumed.video_progress().ok_or("RASL progress")?;
        let recovery = video.recovery.as_ref().ok_or("recovery")?;
        assert_eq!(video.source_segments_consumed, count);
        assert_eq!(video.display_frames_processed, count - 2);
        assert_eq!(video.skipped_rasl_segments, [4, 5]);
        assert_eq!(recovery.discontinuities, 0);
        assert_eq!(recovery.refused_segments, 0);
        assert!(recovery.decode_refusals.is_empty());
        assert_eq!(recovery.continuation_items_processed, count - 2);
        assert!(video.decoder_drained);
        let terminal = resumed.retain(&mut f.deployment, &f.cx)?;
        let expected = LongDwellReport::analyze(
            &f.deployment,
            prepared.plan(),
            rule,
            TOLERANT,
            &limits(),
            &f.cx,
        )?;
        same_report(&resumed.finish(&f.deployment, &f.cx)?, &expected)?;
        let completed =
            RetainedDwellCheckpoint::open(&f.deployment, terminal, &restore_limits(), &f.cx)?;
        let retry = completed.resume(&f.deployment, &restore_limits(), &f.cx)?;
        assert_eq!(retry.video_progress(), Some(video));
        assert!(retry.complete());
        same_report(&retry.finish(&f.deployment, &f.cx)?, &expected)?;
    }
    Ok(())
}

#[test]
fn precodec_work_is_cumulative_across_cold_resume_and_never_becomes_a_tolerated_gap() -> TestResult
{
    let mut f = Fixture::new("incremental-recovery-budget")?;
    let identity = f.ingest(
        "sensor:recovery-budget",
        &damaged_avc(3, 1)?,
        FileFormatHint::AnnexB,
        Some(1_000_000_000),
    )?;
    let plan = plan(identity, 24);
    let limited = LongDwellLimits {
        maximum_pixel_samples: LUMA_CAPACITY * 5,
        ..limits()
    };
    let prepared =
        PreparedIncrementalDwell::new(&f.deployment, plan, rule(), TOLERANT, limited, &f.cx)?;
    let mut running = prepared.start()?;
    running.advance(&f.deployment, 1, &f.cx)?;
    let prefix = running.work();
    let video = running.video_progress();
    let pin = running.retain(&mut f.deployment, &f.cx)?;
    let before = snapshot(&f.deployment);
    let mut tighter = restore_limits();
    tighter.execution.maximum_pixel_samples = limited.maximum_pixel_samples - 1;
    assert!(RetainedDwellCheckpoint::open(&f.deployment, pin, &tighter, &f.cx).is_err());
    let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
    let mut resumed = saved.resume(&f.deployment, &restore_limits(), &f.cx)?;
    assert_eq!(resumed.work(), prefix);
    assert_eq!(resumed.video_progress(), video);
    for owner in [&mut running, &mut resumed] {
        assert!(matches!(
            owner.advance(&f.deployment, 128, &f.cx),
            Err(WatchError::Limit)
        ));
        assert!(!owner.complete());
        assert!(owner.retain(&mut f.deployment, &f.cx).is_err());
        assert!(owner.advance(&f.deployment, 1, &f.cx).is_err());
    }
    assert_eq!(snapshot(&f.deployment), before);
    Ok(())
}

#[test]
fn changed_privacy_refuses_hot_and_cold_recovery_without_publication() -> TestResult {
    let mut f = Fixture::new("incremental-recovery-privacy")?;
    let sensor = "sensor:recovery-privacy";
    let identity = f.ingest(
        sensor,
        &damaged_avc(3, 1)?,
        FileFormatHint::AnnexB,
        Some(1_000_000_000),
    )?;
    let plan = plan(identity, 24);
    let prepared = prepare(&f, &plan, false)?;
    let mut running = prepared.start()?;
    running.advance(&f.deployment, 1, &f.cx)?;
    let pin = running.retain(&mut f.deployment, &f.cx)?;
    let saved = RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx)?;
    let policy = PrivacyMaskPolicy::new(SensorId::parse(sensor)?, [176, 144], &[[0, 0, 16, 16]])?;
    let preview = preview_mask(&f.deployment, &policy)?;
    declare_mask(&mut f.deployment, &policy, preview.approval, &f.cx)?;
    let after = snapshot(&f.deployment);
    assert!(running.advance(&f.deployment, 1, &f.cx).is_err());
    assert!(running.retain(&mut f.deployment, &f.cx).is_err());
    assert!(
        saved
            .resume(&f.deployment, &restore_limits(), &f.cx)
            .is_err()
    );
    assert!(RetainedDwellCheckpoint::open(&f.deployment, pin, &restore_limits(), &f.cx).is_err());
    assert_eq!(snapshot(&f.deployment), after);
    Ok(())
}

#[test]
fn cancellation_before_native_work_poisoned_owner_cannot_checkpoint_or_continue() -> TestResult {
    let mut f = Fixture::new("incremental-recovery-cancel")?;
    let identity = f.ingest(
        "sensor:recovery-cancel",
        &damaged_hevc()?,
        FileFormatHint::Hevc,
        Some(1_000_000_000),
    )?;
    let plan = plan(identity, 6);
    let prepared = prepare(&f, &plan, false)?;
    let mut running = prepared.start()?;
    let before = snapshot(&f.deployment);
    f.cx.set_cancel_at_checkpoint("recorded_video:reserve");
    assert!(running.advance(&f.deployment, 1, &f.cx).is_err());
    assert!(f.cx.is_drain_completed());
    assert!(!running.complete());
    assert!(running.retain(&mut f.deployment, &f.cx).is_err());
    assert!(running.advance(&f.deployment, 1, &f.cx).is_err());
    assert_eq!(snapshot(&f.deployment), before);
    Ok(())
}

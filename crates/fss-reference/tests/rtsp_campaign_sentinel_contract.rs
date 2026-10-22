#![forbid(unsafe_code)]
//! Native quiet-frame detection across exact campaign archives, bounded admission and cold replay.
//! Real retained RTP/AVC/HEVC and the pinned trained package exercise mechanics, not field quality.

#[path = "rtsp_campaign_watch_contract/fixture.rs"]
mod fixture;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use fixture::{Fault, Fixture, SITE, Test, WORK, context, digest};
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_reference::ingest::long_sentinel::retained::{
    LongSentinelReplayLimits, RetainedLongSentinel, rerun_long_sentinel_detection,
};
use fss_reference::ingest::long_watch::LongWatchReport;
use fss_reference::ingest::recorded_watch::WatchPlan;
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::rtsp_campaign_sentinel::*;
use fss_reference::ingest::rtsp_campaign_watch::RtspCampaignWatchError;
use fss_reference::rtsp::campaign_history::{NativeAttemptObservation, NativeBindings};
use fss_reference::{ReferenceDeployment, ScalarExecCx};

const PACKAGE: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");
const PACKAGE_DIGEST: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

impl RtspCampaignSentinelAuthority for fixture::Owner {
    fn permit_sentinel(
        &self,
        plan: &RtspCampaignSentinelPlan,
        destination: &ReferenceDeployment,
    ) -> bool {
        self.calls.fetch_add(1, Ordering::AcqRel);
        if let Ok(mut fault) = self.fault.lock()
            && fault.as_ref().is_some_and(|fault| {
                destination.current_anchor().commit_sequence > fault.after_sequence
            })
            && let Some(fault) = fault.take()
        {
            let result = if let Some(bytes) = fault.bytes {
                fs::write(&fault.path, bytes)
            } else {
                fs::remove_file(&fault.path)
            };
            if result.is_err() {
                return false;
            }
        }
        self.enabled.load(Ordering::Acquire)
            && plan.history.approval == self.campaign.approval
            && destination.site_lineage() == SITE
    }
}

fn package(f: &Fixture, scalar: &ScalarExecCx) -> Test<RgbDetectorPackage> {
    Ok(RgbDetectorPackage::load(
        PACKAGE,
        ContentDigest::parse(PACKAGE_DIGEST)?,
        1 << 36,
        &f.cx,
        scalar,
    )?)
}

fn plan(
    f: &Fixture,
    package: &RgbDetectorPackage,
    max_inferences: usize,
    retain: bool,
) -> RtspCampaignSentinelPlan {
    RtspCampaignSentinelPlan {
        history: f.plan.history,
        history_root: f.plan.history_root.clone(),
        bindings: f.plan.bindings.clone(),
        interpretation: f.plan.interpretation,
        package_digest: package.archive_digest(),
        backend: package.model().backend(),
        minimum_score_ppm: None,
        sampling: RtspCampaignSentinelConfig {
            every_frames: 2,
            burst_frames: 1,
            max_inferences,
        },
        retain,
    }
}

fn limits(f: &Fixture) -> RtspCampaignSentinelLimits {
    let mut limits = RtspCampaignSentinelLimits {
        history: f.limits.history,
        history_publication: f.limits.history_publication,
        ..Default::default()
    };
    // Explicit conservative native capacities make a shared coded-pixel refusal measurable.
    limits.sentinel.package.h264.max_width = 256;
    limits.sentinel.package.h264.max_height = 256;
    limits.sentinel.package.h264.max_macroblocks = 256;
    limits.sentinel.package.h265.max_width = 256;
    limits.sentinel.package.h265.max_height = 256;
    limits.sentinel.package.h265.max_luma_samples = 256 * 256;
    limits.sentinel.maximum_pixel_samples = 1_000_000;
    limits
}

fn run(
    f: &mut Fixture,
    package: &RgbDetectorPackage,
    plan: &RtspCampaignSentinelPlan,
    limits: &RtspCampaignSentinelLimits,
    scalar: &ScalarExecCx,
) -> Result<RtspCampaignSentinelReport, RtspCampaignSentinelError> {
    let sources = f.archives.iter().map(Option::as_ref).collect::<Vec<_>>();
    process_rtsp_campaign_sentinel(
        &sources,
        f.destination.as_mut().expect("fixture destination"),
        package,
        PACKAGE,
        plan,
        limits,
        &f.owner,
        &f.history_cx,
        &f.cx,
        scalar,
        &mut WorkBudget::new(WORK),
    )
}

fn tree(root: &Path) -> Test<BTreeMap<PathBuf, Vec<u8>>> {
    let mut files = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else {
                files.insert(entry.path(), fs::read(entry.path())?);
            }
        }
    }
    Ok(files)
}

#[test]
fn quiet_avc_and_independent_hevc_reach_native_model_under_one_round_robin_allowance() -> Test {
    let mut f = Fixture::new("campaign-sentinel-native", 8)?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let plan = plan(&f, &package, 3, false);
    let limits = limits(&f);
    let effects = f.target().effects().last_root();
    let report = run(&mut f, &package, &plan, &limits, &scalar)?;
    assert_eq!(report.plan_digest(), plan.digest(&limits)?);
    assert_eq!(report.history().pin(), plan.history);
    assert_eq!(report.analysis_basis(), f.target().current_anchor());
    assert_eq!(report.attempts().len(), 4);
    let expected = [(6, 2, 2, vec![0, 2]), (4, 1, 1, vec![0])];
    let mut inferences = 0;
    for (attempt, (frames, windows, pages, selected)) in report.attempts().iter().zip(expected) {
        assert_eq!(attempt.status(), RtspCampaignSentinelStatus::Analyzed);
        let import = attempt.import().ok_or("native retained import")?;
        let native = attempt.sentinel_report().ok_or("native sentinel report")?;
        assert_eq!(import.frames, frames);
        assert_eq!(attempt.windows(), windows);
        assert_eq!(attempt.pages(), pages);
        assert_eq!(attempt.catalogued_pictures(), frames as u64);
        assert_eq!(attempt.decoded_pictures(), frames as u64);
        assert_eq!(native.usage().decoded_frames, frames);
        assert_eq!(
            native
                .plan()
                .selected_segments()
                .into_iter()
                .collect::<Vec<_>>(),
            selected
        );
        assert_eq!(native.usage().inferences, selected.len());
        assert!(native.usage().execution_macs > 0);
        assert_eq!(attempt.allocation().admitted_inferences, selected.len());
        assert!(attempt.retained().is_none());
        assert!(native.json().contains("\"motion_independent\":true"));
        assert!(native.json().contains("\"model_outputs\":\"uncalibrated\""));
        assert!(native.json().contains("\"absence_certifiable\":false"));
        inferences += native.usage().inferences;
    }
    assert_eq!(
        inferences, 3,
        "the second archive gets a turn before the first consumes all slots"
    );
    let avc = &report.attempts()[0];
    assert_eq!(avc.recorded_durable_pictures(), Some(8));
    assert_eq!(avc.recorded_pictures_without_catalog(), Some(2));
    assert!(
        !avc.recorded()
            .finish
            .as_ref()
            .ok_or("finish")?
            .settled_success
    );
    let watch = LongWatchReport::analyze(
        f.target(),
        &WatchPlan {
            import_identity: avc.import().ok_or("AVC import")?.import_identity,
            interpretation: f.plan.interpretation,
            first_segment: 0,
            segment_count: 6,
            zones: f.plan.zones.clone(),
            detector: f.plan.detector,
            tracker: f.plan.tracker,
        },
        f.plan.options,
        &f.limits.watch,
        &f.cx,
    )?;
    assert!(
        watch.candidates().is_empty(),
        "quiet footage has no foreground entry candidate"
    );
    assert_eq!(
        report.attempts()[2].status(),
        RtspCampaignSentinelStatus::RecordedNoDurablePictures
    );
    assert_eq!(
        report.attempts()[3].status(),
        RtspCampaignSentinelStatus::StartedWithoutRetainedFinish
    );
    assert_eq!(report.attempts()[3].recorded_durable_pictures(), None);
    assert_eq!(f.target().effects().last_root(), effects);
    let json = report.to_json(f.target().current_anchor().commit_sequence)?;
    for text in [
        "\"absence_certifiable\":false",
        "\"event_publication_authorized\":false",
        "\"recorded_pictures_without_catalog\":2",
        "\"recorded_durable_pictures\":null",
    ] {
        assert!(json.contains(text), "missing {text}");
    }
    Ok(())
}

#[test]
fn global_exhaustion_and_short_recordings_remain_explicit_after_complete_import() -> Test {
    let mut f = Fixture::new("campaign-sentinel-allocation", 8)?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let mut plan = plan(&f, &package, 1, false);
    let limits = limits(&f);
    let report = run(&mut f, &package, &plan, &limits, &scalar)?;
    let skipped = &report.attempts()[1];
    assert_eq!(skipped.status(), RtspCampaignSentinelStatus::BudgetSkipped);
    assert_eq!(skipped.catalogued_pictures(), 4);
    assert_eq!(skipped.decoded_pictures(), 0);
    assert_eq!(skipped.allocation().admitted_inferences, 0);
    assert!(skipped.allocation().budget_skipped_bursts > 0);
    assert!(skipped.sentinel_report().is_none());
    plan.sampling = RtspCampaignSentinelConfig {
        every_frames: 8,
        burst_frames: 8,
        max_inferences: 8,
    };
    let report = run(&mut f, &package, &plan, &limits, &scalar)?;
    for attempt in &report.attempts()[..2] {
        assert_eq!(
            attempt.status(),
            RtspCampaignSentinelStatus::TooShortForBurst
        );
        assert!(attempt.import().ok_or("complete import")?.reused);
        assert_eq!(attempt.allocation().admitted_inferences, 0);
        assert!(attempt.sentinel_report().is_none());
    }
    Ok(())
}

#[test]
fn exact_older_start_only_prefix_never_reads_a_later_recording_or_infers_empty_scene() -> Test {
    let mut f = Fixture::new("campaign-sentinel-start-only", 8)?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let mut plan = plan(&f, &package, 2, false);
    let limits = limits(&f);
    plan.history = f.first_start;
    plan.bindings.truncate(1);
    plan.bindings[0].selection = None;
    f.archives = vec![None];
    let before = tree(f.target().root())?;
    let report = run(&mut f, &package, &plan, &limits, &scalar)?;
    assert_eq!(report.attempts().len(), 1);
    let attempt = &report.attempts()[0];
    assert_eq!(
        attempt.status(),
        RtspCampaignSentinelStatus::StartedWithoutRetainedFinish
    );
    assert_eq!(attempt.recorded_durable_pictures(), None);
    assert!(attempt.import().is_none());
    assert!(attempt.sentinel_report().is_none());
    assert_eq!(tree(f.target().root())?, before);
    Ok(())
}

#[test]
fn unavailable_and_unindexed_observations_do_not_become_zero_picture_success() -> Test {
    for unavailable in [true, false] {
        let mut f = Fixture::new(
            if unavailable {
                "sentinel-unavailable"
            } else {
                "sentinel-unindexed"
            },
            8,
        )?;
        f.finish_fourth(if unavailable {
            None
        } else {
            Some(NativeAttemptObservation {
                complete: false,
                error_id: Some("ERR-CAPTURE-RTSP-SOURCE-001".into()),
                retry: None,
                durable_pictures: 3,
                recovery_required: true,
                bindings: NativeBindings::default(),
            })
        })?;
        let scalar = ScalarExecCx::new();
        let package = package(&f, &scalar)?;
        let mut plan = plan(&f, &package, 8, false);
        plan.sampling = RtspCampaignSentinelConfig {
            every_frames: 8,
            burst_frames: 8,
            max_inferences: 8,
        };
        let limits = limits(&f);
        let report = run(&mut f, &package, &plan, &limits, &scalar)?;
        let attempt = &report.attempts()[3];
        assert_eq!(
            attempt.status(),
            if unavailable {
                RtspCampaignSentinelStatus::NativeObservationUnavailable
            } else {
                RtspCampaignSentinelStatus::RecordedPicturesWithoutCatalog
            }
        );
        assert_eq!(
            attempt.recorded_durable_pictures(),
            if unavailable { None } else { Some(3) }
        );
        assert_eq!(
            attempt.recorded_pictures_without_catalog(),
            if unavailable { None } else { Some(3) }
        );
        assert!(attempt.sentinel_report().is_none());
        assert!(attempt.import().is_none());
    }
    Ok(())
}

#[test]
fn corrupt_later_archive_refuses_before_any_import_or_model_execution() -> Test {
    let mut f = Fixture::new("campaign-sentinel-preflight", 8)?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let plan = plan(&f, &package, 2, false);
    let limits = limits(&f);
    let before = tree(f.target().root())?;
    fs::write(&f.source_objects[1], b"corrupt later HEVC original")?;
    f.cx.set_cancel_at_checkpoint_occurrence("package_detect:frame", 1);
    assert!(matches!(
        run(&mut f, &package, &plan, &limits, &scalar),
        Err(RtspCampaignSentinelError::Source(
            RtspCampaignWatchError::Import(_)
        ))
    ));
    assert!(
        !f.cx.is_cancelled(),
        "no first inference after incomplete all-source preflight"
    );
    assert_eq!(tree(f.target().root())?, before);
    Ok(())
}

#[test]
fn model_identity_threshold_current_authority_and_shared_work_refuse_before_mutation() -> Test {
    let mut f = Fixture::new("campaign-sentinel-admission", 8)?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let plan = plan(&f, &package, 2, false);
    let limits = limits(&f);
    let before = tree(f.target().root())?;
    for mutation in 0..3 {
        let mut changed = plan.clone();
        match mutation {
            0 => changed.package_digest = digest("wrong package"),
            1 => changed.minimum_score_ppm = Some(1_000_001),
            _ => changed.sampling.max_inferences = 1025,
        }
        assert!(run(&mut f, &package, &changed, &limits, &scalar).is_err());
        assert_eq!(tree(f.target().root())?, before);
    }
    f.owner.enabled.store(false, Ordering::Release);
    let mut work = WorkBudget::new(WORK);
    let sources = f.archives.iter().map(Option::as_ref).collect::<Vec<_>>();
    assert!(
        process_rtsp_campaign_sentinel(
            &sources,
            f.destination.as_mut().ok_or("target")?,
            &package,
            PACKAGE,
            &plan,
            &limits,
            &f.owner,
            &f.history_cx,
            &f.cx,
            &scalar,
            &mut work
        )
        .is_err()
    );
    assert_eq!(work.remaining(), WORK);
    f.owner.enabled.store(true, Ordering::Release);
    assert!(
        process_rtsp_campaign_sentinel(
            &sources,
            f.destination.as_mut().ok_or("target")?,
            &package,
            PACKAGE,
            &plan,
            &limits,
            &f.owner,
            &f.history_cx,
            &f.cx,
            &scalar,
            &mut WorkBudget::new(1)
        )
        .is_err()
    );
    assert_eq!(tree(f.target().root())?, before);
    Ok(())
}

#[test]
fn shared_pixel_pool_cannot_refill_at_second_archive_and_completed_imports_are_retryable() -> Test {
    let mut f = Fixture::new("campaign-sentinel-pixels", 8)?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let plan = plan(&f, &package, 2, false);
    let limits = limits(&f);
    let initial = f.target().current_anchor().clone();
    let mut low = limits;
    low.sentinel.maximum_pixel_samples = 6 * 256 * 256;
    assert!(run(&mut f, &package, &plan, &low, &scalar).is_err());
    assert!(f.target().current_anchor().commit_sequence > initial.commit_sequence);
    let report = run(&mut f, &package, &plan, &limits, &scalar)?;
    assert!(
        report
            .attempts()
            .iter()
            .filter_map(|a| a.import())
            .all(|i| i.reused)
    );
    let first = report.attempts()[0]
        .sentinel_report()
        .ok_or("first report")?;
    let second = report.attempts()[1]
        .sentinel_report()
        .ok_or("second report")?;
    assert!(second.limits().maximum_pixel_samples < first.limits().maximum_pixel_samples);
    assert_eq!(
        first.limits().maximum_pixel_samples - second.limits().maximum_pixel_samples,
        first.usage().video_coded_luma_capacity
    );
    assert!(
        first.usage().video_coded_luma_capacity + second.usage().video_coded_luma_capacity
            <= limits.sentinel.maximum_pixel_samples
    );
    Ok(())
}

#[test]
fn retained_native_reports_retry_exactly_and_replay_after_archives_and_loose_model_are_unavailable()
-> Test {
    let mut f = Fixture::new("campaign-sentinel-cold", 8)?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let plan = plan(&f, &package, 2, true);
    let limits = limits(&f);
    let first = run(&mut f, &package, &plan, &limits, &scalar)?;
    let anchor = f.target().current_anchor().clone();
    let effects = f.target().effects().last_root();
    let report_pins = first
        .attempts()
        .iter()
        .filter_map(|attempt| attempt.retained())
        .map(|retained| {
            (
                retained.report_digest(),
                retained.root(),
                retained.recipe_digest(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(report_pins.len(), 2);
    let retry = run(&mut f, &package, &plan, &limits, &scalar)?;
    assert_eq!(f.target().current_anchor(), &anchor);
    assert_eq!(f.target().effects().last_root(), effects);
    for (a, b) in first.attempts().iter().zip(retry.attempts()) {
        assert_eq!(a.status(), b.status());
        if let Some(a) = a.sentinel_report() {
            assert_eq!(
                a.digest(),
                b.sentinel_report().ok_or("retry report")?.digest()
            );
            assert_eq!(a.json(), b.sentinel_report().ok_or("retry report")?.json());
            assert!(b.import().ok_or("retry import")?.reused);
        }
    }
    let archive_paths = f
        .archives
        .iter()
        .filter_map(|a| a.as_ref().map(|a| a.root_dir().to_path_buf()))
        .collect::<Vec<_>>();
    f.archives.clear();
    for path in archive_paths {
        fs::rename(&path, path.with_extension("offline"))?;
    }
    drop(package);
    drop(first);
    drop(retry);
    drop(f.destination.take());
    f.cx.drain_and_finalize();
    let root = f.directory.0.join("destination");
    f.cx = context(&root, false)?;
    f.destination = Some(ReferenceDeployment::reopen(&root, SITE, &f.cx)?);
    let before = tree(f.target().root())?;
    let ceilings = LongSentinelReplayLimits {
        execution: limits.sentinel,
        ..Default::default()
    };
    for (report, root, recipe) in report_pins {
        let retained = RetainedLongSentinel::open(f.target(), report, &ceilings, &f.cx)?;
        assert_eq!(retained.root(), root);
        assert_eq!(retained.recipe_digest(), recipe);
        assert_eq!(
            retained.package_digest(),
            ContentDigest::parse(PACKAGE_DIGEST)?
        );
        let replayed = rerun_long_sentinel_detection(
            f.target(),
            report,
            &ceilings,
            &f.cx,
            &ScalarExecCx::new(),
        )?;
        assert_eq!(replayed.digest(), report);
    }
    assert_eq!(tree(f.target().root())?, before);
    assert_eq!(f.target().current_anchor(), &anchor);
    Ok(())
}

#[test]
fn cancellation_between_native_phases_returns_no_partial_report_and_reuses_prior_commits() -> Test {
    for (stage, occurrence, imported) in [
        (STAGE_RTSP_CAMPAIGN_SENTINEL_PREFLIGHT, 2, 0),
        (STAGE_RTSP_CAMPAIGN_SENTINEL_IMPORT, 2, 1),
        (STAGE_RTSP_CAMPAIGN_SENTINEL_ANALYZE, 2, 2),
        (STAGE_RTSP_CAMPAIGN_SENTINEL_RETAIN, 2, 2),
        (STAGE_RTSP_CAMPAIGN_SENTINEL_RELEASE, 1, 2),
    ] {
        let mut f = Fixture::new(stage.rsplit(':').next().ok_or("stage")?, 8)?;
        let scalar = ScalarExecCx::new();
        let package = package(&f, &scalar)?;
        let plan = plan(&f, &package, 2, true);
        let limits = limits(&f);
        f.cx.set_cancel_at_checkpoint_occurrence(stage, occurrence);
        assert!(
            run(&mut f, &package, &plan, &limits, &scalar).is_err(),
            "{stage}"
        );
        assert!(f.cx.is_drain_completed(), "{stage}");
        f.cx = context(&f.directory.0.join("destination"), false)?;
        let report = run(&mut f, &package, &plan, &limits, &ScalarExecCx::new())?;
        assert_eq!(
            report
                .attempts()
                .iter()
                .filter_map(|a| a.import())
                .filter(|i| i.reused)
                .count(),
            imported,
            "{stage}"
        );
    }
    Ok(())
}

#[test]
fn final_history_and_original_checks_reject_damage_after_durable_imports() -> Test {
    for history in [false, true] {
        let mut f = Fixture::new(
            if history {
                "sentinel-history-cut"
            } else {
                "sentinel-source-cut"
            },
            8,
        )?;
        let scalar = ScalarExecCx::new();
        let package = package(&f, &scalar)?;
        let plan = plan(&f, &package, 2, false);
        let limits = limits(&f);
        let path = if history {
            f.history_object.clone()
        } else {
            f.source_objects[0].clone()
        };
        let original = fs::read(&path)?;
        let before = f.target().current_anchor().commit_sequence;
        *f.owner.fault.lock().map_err(|_| "fault mutex")? = Some(Fault {
            after_sequence: before,
            path: path.clone(),
            bytes: Some(b"changed after all-source preflight".to_vec()),
        });
        assert!(run(&mut f, &package, &plan, &limits, &scalar).is_err());
        assert!(f.target().current_anchor().commit_sequence > before);
        fs::write(path, original)?;
        let report = run(&mut f, &package, &plan, &limits, &scalar)?;
        assert_eq!(
            report
                .attempts()
                .iter()
                .filter_map(|a| a.import())
                .filter(|i| i.reused)
                .count(),
            2
        );
    }
    Ok(())
}

#![forbid(unsafe_code)]
//! Real retained HTTP/JPEG histories reach the pinned trained model without foreground gating.
//! These synthetic scenes test composition, custody and resource boundaries, not field quality.

#[path = "http_history_watch_contract/fixture.rs"]
mod fixture;

use std::cell::Cell;
use std::fs;
use std::path::PathBuf;

use fixture::{Fixture, Owner, SITE, Test, WORK, archive_limits, context, response, scene};
use fss_codec_mjpeg::DecodeBudget;
use fss_core::{ContentDigest, DigestAlgorithm, TimestampNs};
use fss_geometry::WorkBudget;
use fss_publication::NeverCancel;
use fss_reference::http_reconnect_history::{BoundaryOutcome, VerifiedReconnectHistory};
use fss_reference::ingest::http_archive::HttpWireArchive;
use fss_reference::ingest::http_history_sentinel::*;
use fss_reference::ingest::long_sentinel::retained::{
    LongSentinelReplayLimits, RetainedLongSentinel, rerun_long_sentinel_detection,
};
use fss_reference::ingest::long_watch::LongWatchReport;
use fss_reference::ingest::privacy_mask::{
    PrivacyMaskPolicy, current_mask, declare_mask, preview_mask,
};
use fss_reference::ingest::recorded_watch::WatchPlan;
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::{ReferenceDeployment, ScalarExecCx};

const PACKAGE: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");
const PACKAGE_DIGEST: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

impl HttpHistorySentinelAuthority for Owner {
    fn permit_sentinel(
        &self,
        _: &HttpHistorySentinelPlan,
        destination: &ReferenceDeployment,
    ) -> bool {
        self.0 && destination.site_lineage() == SITE
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
) -> HttpHistorySentinelPlan {
    HttpHistorySentinelPlan {
        history: f.plan.history,
        bindings: f.plan.bindings.clone(),
        interpretation: f.plan.interpretation,
        package_digest: package.archive_digest(),
        backend: package.model().backend(),
        minimum_score_ppm: None,
        sampling: HttpHistorySentinelConfig {
            every_frames: 2,
            burst_frames: 1,
            max_inferences,
        },
        retain,
    }
}
fn limits(f: &Fixture) -> HttpHistorySentinelLimits {
    HttpHistorySentinelLimits {
        history: f.limits.history,
        maximum_frames_per_generation: f.limits.maximum_frames_per_generation,
        maximum_bytes_per_generation: f.limits.maximum_bytes_per_generation,
        ..Default::default()
    }
}
fn run(
    f: &mut Fixture,
    package: &RgbDetectorPackage,
    plan: &HttpHistorySentinelPlan,
    limits: &HttpHistorySentinelLimits,
    scalar: &ScalarExecCx,
) -> Result<HttpHistorySentinelReport, HttpHistorySentinelError> {
    process_http_history_sentinel(
        &f.source,
        &mut f.target,
        package,
        PACKAGE,
        plan,
        limits,
        &Owner(true),
        &f.cx,
        scalar,
        &mut WorkBudget::new(WORK),
        &mut DecodeBudget::new(WORK),
    )
}
fn original(f: &Fixture, generation: usize) -> Test<ContentDigest> {
    let history = VerifiedReconnectHistory::load(
        &f.source,
        f.plan.history,
        f.limits.history,
        &NeverCancel,
        &mut WorkBudget::new(WORK),
    )?;
    let boundary = &history.boundaries()[generation];
    let archive = HttpWireArchive::load(
        &f.source,
        boundary.scope(),
        boundary.prefix(),
        archive_limits(),
        &NeverCancel,
        &mut WorkBudget::new(WORK),
    )?;
    let raw = archive.reads().next().ok_or("original response read")?.1;
    Ok(ContentDigest::new(DigestAlgorithm::Sha256, raw.sha256))
}

#[test]
fn quiet_generations_reach_native_model_under_one_round_robin_allowance_without_events() -> Test {
    let mut f = Fixture::new(&[response(&scene(6, 6)?), response(&scene(4, 4)?)])?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let plan = plan(&f, &package, 3, false);
    let limits = limits(&f);
    let effects = f.target.effects().last_root();
    let report = run(&mut f, &package, &plan, &limits, &scalar)?;
    assert_eq!(report.plan_digest(), plan.digest(&limits)?);
    assert_eq!(report.history_pin(), f.plan.history);
    assert_eq!(report.analysis_basis(), f.target.current_anchor());
    assert_eq!(report.generations().len(), 2);
    assert_eq!(report.usage().inferences, 3);
    assert_eq!(
        report.usage().decoded_frames,
        3,
        "MJPEG decodes selected images only"
    );
    for (row, selected) in report.generations().iter().zip([vec![0, 2], vec![0]]) {
        assert_eq!(row.status(), HttpHistorySentinelStatus::Analyzed);
        assert_eq!(row.native_outcome(), BoundaryOutcome::NativeComplete);
        let import = row.import().ok_or("native import")?;
        let native = row.sentinel_report().ok_or("native sentinel")?;
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
        assert_eq!(
            native.reports().len(),
            selected.len(),
            "separate one-frame bursts never join tracks"
        );
        assert!(row.retained().is_none());
        let watch = LongWatchReport::analyze(
            &f.target,
            &WatchPlan {
                import_identity: import.import_identity,
                interpretation: f.plan.interpretation,
                first_segment: 0,
                segment_count: import.frames,
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
            "quiet scene has no foreground entry candidate"
        );
    }
    assert_eq!(f.target.effects().last_root(), effects);
    assert!(
        !f.target
            .ledger()
            .batches()
            .iter()
            .any(|batch| batch.deltas.iter().any(|d| d.family == "event"))
    );
    let json = report.to_json(f.target.current_anchor().commit_sequence)?;
    for text in [
        "\"motion_independent\":true",
        "\"foreground_gate_required\":false",
        "\"tracker_continuity_across_generations\":false",
        "\"tracker_continuity_across_bursts\":false",
        "\"event_publication_authorized\":false",
        "\"absence_certifiable\":false",
        "\"model_outputs\":\"uncalibrated\"",
    ] {
        assert!(json.contains(text), "missing {text}");
    }
    Ok(())
}

#[test]
fn empty_failed_short_and_quota_skipped_generations_preserve_exact_native_outcomes() -> Test {
    let incomplete = b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=camera\r\nContent-Length: 9999\r\n\r\n--camera\r\n".to_vec();
    let mut failed = response(&scene(4, 4)?);
    // The fourth JPEG is intact, but its following MIME delimiter is not. Only the first
    // three source-mapped parts are complete; JPEG EOI alone never releases the last part.
    failed.truncate(failed.len() - 6);
    let mut f = Fixture::new(&[
        Vec::new(),
        incomplete,
        response(&scene(1, 1)?),
        failed,
        response(&scene(4, 4)?),
    ])?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let mut plan = plan(&f, &package, 2, false);
    plan.sampling = HttpHistorySentinelConfig {
        every_frames: 3,
        burst_frames: 2,
        max_inferences: 2,
    };
    let limits = limits(&f);
    let report = run(&mut f, &package, &plan, &limits, &scalar)?;
    let rows = report.generations();
    assert_eq!(
        rows.iter().map(|r| r.status()).collect::<Vec<_>>(),
        [
            HttpHistorySentinelStatus::EmptyResponse,
            HttpHistorySentinelStatus::NoCompleteJpeg,
            HttpHistorySentinelStatus::TooShortForBurst,
            HttpHistorySentinelStatus::Analyzed,
            HttpHistorySentinelStatus::BudgetSkipped,
        ]
    );
    for index in [0, 1, 3] {
        assert_eq!(rows[index].native_outcome(), BoundaryOutcome::SourceFailed);
    }
    assert!(rows[..2].iter().all(|r| r.import().is_none()));
    assert!(rows[2].sentinel_report().is_none());
    assert_eq!(rows[3].import().ok_or("failed-prefix originals")?.frames, 3);
    assert_eq!(rows[3].allocation().admitted_inferences, 2);
    assert_eq!(rows[4].allocation().budget_skipped_bursts, 1);
    assert!(rows[4].import().is_some());
    assert!(rows[4].sentinel_report().is_none());
    let json = report.to_json(f.target.current_anchor().commit_sequence)?;
    assert!(json.contains("\"unsampled_ranges\":[{\"first_segment\":0,\"segment_count\":4}]"));
    assert_eq!(report.usage().inferences, 2);
    Ok(())
}

#[test]
fn package_mapping_authority_and_shared_work_refuse_before_any_destination_mutation() -> Test {
    let mut f = Fixture::new(&[response(&scene(2, 2)?), response(&scene(2, 2)?)])?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let plan = plan(&f, &package, 2, false);
    let limits = limits(&f);
    let before = f.target.current_anchor().clone();
    let roots = f.target.publisher().visible_roots().count();
    for mutation in 0..5 {
        let mut changed = plan.clone();
        match mutation {
            0 => changed.package_digest = ContentDigest::sha256(b"wrong model archive"),
            1 => changed.minimum_score_ppm = Some(1_000_001),
            2 => changed.bindings.swap(0, 1),
            3 => changed.bindings[1].generation = 9,
            _ => changed.sampling.max_inferences = MAX_HTTP_HISTORY_SENTINEL_INFERENCES + 1,
        }
        assert!(run(&mut f, &package, &changed, &limits, &scalar).is_err());
        assert_eq!(f.target.current_anchor(), &before);
    }
    let mut work = WorkBudget::new(WORK);
    assert!(matches!(
        process_http_history_sentinel(
            &f.source,
            &mut f.target,
            &package,
            PACKAGE,
            &plan,
            &limits,
            &Owner(false),
            &f.cx,
            &scalar,
            &mut work,
            &mut DecodeBudget::new(WORK)
        ),
        Err(HttpHistorySentinelError::Denied)
    ));
    assert_eq!(work.remaining(), WORK);
    assert!(
        process_http_history_sentinel(
            &f.source,
            &mut f.target,
            &package,
            PACKAGE,
            &plan,
            &limits,
            &Owner(true),
            &f.cx,
            &scalar,
            &mut WorkBudget::new(1),
            &mut DecodeBudget::new(WORK)
        )
        .is_err()
    );
    let later_original = original(&f, 1)?;
    fs::write(
        f.source.spool().object_path(later_original),
        b"corrupt later original response",
    )?;
    f.cx.set_cancel_at_checkpoint_occurrence(STAGE_HTTP_HISTORY_SENTINEL_ANALYZE, 1);
    assert!(matches!(
        run(&mut f, &package, &plan, &limits, &scalar),
        Err(HttpHistorySentinelError::Source(_))
    ));
    assert!(
        !f.cx.is_cancelled(),
        "all history originals are checked before first model phase"
    );
    assert_eq!(f.target.current_anchor(), &before);
    assert_eq!(f.target.publisher().visible_roots().count(), roots);
    Ok(())
}

#[test]
fn exhausted_global_pixels_cannot_refill_at_next_generation_and_native_imports_retry_exactly()
-> Test {
    let mut f = Fixture::new(&[response(&scene(2, 2)?), response(&scene(2, 2)?)])?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let plan = plan(&f, &package, 2, false);
    let limits = limits(&f);
    let mut low = limits;
    low.sentinel.maximum_pixel_samples = 96 * 48;
    let before = f.target.current_anchor().clone();
    assert!(run(&mut f, &package, &plan, &low, &scalar).is_err());
    assert!(f.target.current_anchor().commit_sequence > before.commit_sequence);
    let report = run(&mut f, &package, &plan, &limits, &scalar)?;
    let first = report.generations()[0]
        .sentinel_report()
        .ok_or("first native report")?;
    let second = report.generations()[1]
        .sentinel_report()
        .ok_or("second native report")?;
    assert_eq!(
        first.limits().maximum_pixel_samples - second.limits().maximum_pixel_samples,
        first.usage().pixel_samples
    );
    assert_eq!(
        first.limits().package.jpeg_work_units - second.limits().package.jpeg_work_units,
        first.usage().jpeg_work_units
    );
    assert_eq!(
        first.limits().package.detection_work_units - second.limits().package.detection_work_units,
        first.usage().detection_work_units
    );
    assert_eq!(
        first.limits().maximum_report_bytes - second.limits().maximum_report_bytes,
        first.json().len()
    );
    assert!(
        report
            .generations()
            .iter()
            .all(|r| r.import().is_some_and(|i| i.reused))
    );
    Ok(())
}

#[test]
fn interrupted_import_cold_retry_reuses_completed_originals_without_a_progress_journal() -> Test {
    let mut f = Fixture::new(&[response(&scene(2, 2)?), response(&scene(3, 3)?)])?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let plan = plan(&f, &package, 2, false);
    let limits = limits(&f);
    let before = f.target.current_anchor().clone();
    f.cx.set_cancel_at_checkpoint_occurrence(STAGE_HTTP_HISTORY_SENTINEL_IMPORT, 2);
    assert!(run(&mut f, &package, &plan, &limits, &scalar).is_err());
    assert!(f.target.current_anchor().commit_sequence > before.commit_sequence);
    drop(f.target);
    f.cx = context(&f.target_dir.0)?;
    f.target = ReferenceDeployment::open(&f.target_dir.0, SITE, &f.cx)?;
    let report = run(&mut f, &package, &plan, &limits, &ScalarExecCx::new())?;
    assert!(
        report.generations()[0]
            .import()
            .ok_or("first reused import")?
            .reused
    );
    assert!(
        !report.generations()[1]
            .import()
            .ok_or("second new import")?
            .reused
    );
    let complete = f.target.current_anchor().clone();
    let retry = run(&mut f, &package, &plan, &limits, &ScalarExecCx::new())?;
    assert_eq!(f.target.current_anchor(), &complete);
    for (a, b) in report.generations().iter().zip(retry.generations()) {
        assert!(b.import().ok_or("retry")?.reused);
        assert_eq!(
            a.sentinel_report().ok_or("first report")?.digest(),
            b.sentinel_report().ok_or("retry report")?.digest()
        );
    }
    Ok(())
}

#[test]
fn retained_reports_replay_cold_after_original_archive_and_loose_model_go_offline() -> Test {
    let mut f = Fixture::new(&[response(&scene(2, 2)?), response(&scene(2, 2)?)])?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let plan = plan(&f, &package, 2, true);
    let limits = limits(&f);
    let first = run(&mut f, &package, &plan, &limits, &scalar)?;
    let anchor = f.target.current_anchor().clone();
    let effects = f.target.effects().last_root();
    let pins = first
        .generations()
        .iter()
        .filter_map(|row| row.retained())
        .map(|r| (r.report_digest(), r.root(), r.recipe_digest()))
        .collect::<Vec<_>>();
    assert_eq!(pins.len(), 2);
    let retry = run(&mut f, &package, &plan, &limits, &scalar)?;
    assert_eq!(f.target.current_anchor(), &anchor);
    for (a, b) in first.generations().iter().zip(retry.generations()) {
        assert_eq!(
            a.sentinel_report().ok_or("report")?.json(),
            b.sentinel_report().ok_or("retry report")?.json()
        );
        assert_eq!(
            b.retained().ok_or("retained retry")?.status().as_str(),
            "already_retained"
        );
    }
    drop(first);
    drop(retry);
    drop(package);
    let Fixture {
        source_dir,
        target_dir,
        source,
        target,
        cx,
        ..
    } = f;
    drop(source);
    drop(target);
    cx.drain_and_finalize();
    drop(cx);
    let offline = source_dir.0.with_extension("offline");
    fs::rename(&source_dir.0, &offline)?;
    let _offline_cleanup = fixture::Directory(offline);
    let cx = context(&target_dir.0)?;
    let target = ReferenceDeployment::reopen(&target_dir.0, SITE, &cx)?;
    let ceilings = LongSentinelReplayLimits {
        execution: limits.sentinel,
        ..Default::default()
    };
    for (report, root, recipe) in pins {
        let retained = RetainedLongSentinel::open(&target, report, &ceilings, &cx)?;
        assert_eq!(retained.root(), root);
        assert_eq!(retained.recipe_digest(), recipe);
        assert_eq!(
            retained.package_digest(),
            ContentDigest::parse(PACKAGE_DIGEST)?
        );
        let replay =
            rerun_long_sentinel_detection(&target, report, &ceilings, &cx, &ScalarExecCx::new())?;
        assert_eq!(replay.digest(), report);
    }
    assert_eq!(target.current_anchor(), &anchor);
    assert_eq!(target.effects().last_root(), effects);
    Ok(())
}

#[test]
fn interrupted_native_retention_reconciles_prior_aggregate_before_retaining_next_generation() -> Test
{
    let mut f = Fixture::new(&[response(&scene(1, 1)?), response(&scene(1, 1)?)])?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let plan = plan(&f, &package, 2, true);
    let limits = limits(&f);
    let effects = f.target.effects().last_root();
    f.cx.set_cancel_at_checkpoint_occurrence(STAGE_HTTP_HISTORY_SENTINEL_RETAIN, 2);
    assert!(run(&mut f, &package, &plan, &limits, &scalar).is_err());
    assert_eq!(
        f.target
            .ledger()
            .batches()
            .iter()
            .flat_map(|b| &b.deltas)
            .filter(|d| d.family == "long_sentinel_detection")
            .count(),
        1
    );
    drop(f.target);
    f.cx = context(&f.target_dir.0)?;
    f.target = ReferenceDeployment::reopen(&f.target_dir.0, SITE, &f.cx)?;
    let report = run(&mut f, &package, &plan, &limits, &ScalarExecCx::new())?;
    assert!(
        report
            .generations()
            .iter()
            .all(|r| r.import().is_some_and(|i| i.reused))
    );
    assert_eq!(
        report.generations()[0]
            .retained()
            .ok_or("reconciled aggregate")?
            .status()
            .as_str(),
        "already_retained"
    );
    assert_eq!(
        report.generations()[1]
            .retained()
            .ok_or("new aggregate")?
            .status()
            .as_str(),
        "retained"
    );
    assert_eq!(
        f.target
            .ledger()
            .batches()
            .iter()
            .flat_map(|b| &b.deltas)
            .filter(|d| d.family == "long_sentinel_detection")
            .count(),
        2
    );
    assert_eq!(f.target.effects().last_root(), effects);
    Ok(())
}

#[test]
fn every_generation_applies_current_destination_privacy_before_native_model_execution() -> Test {
    let mut f = Fixture::new(&[response(&scene(1, 1)?), response(&scene(1, 0)?)])?;
    let policy = PrivacyMaskPolicy::new(
        f.plan.bindings[0].sensor.clone(),
        [96, 48],
        &[[0, 0, 96, 48]],
    )?;
    let approval = preview_mask(&f.target, &policy)?.approval;
    declare_mask(&mut f.target, &policy, approval, &f.cx)?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let plan = plan(&f, &package, 2, false);
    let limits = limits(&f);
    let report = run(&mut f, &package, &plan, &limits, &scalar)?;
    let mask = current_mask(&f.target, &f.plan.bindings[0].sensor)?;
    let mut identities = Vec::new();
    let mut originals = Vec::new();
    for row in report.generations() {
        let child = &row.sentinel_report().ok_or("native report")?.reports()[0];
        assert_eq!(child.privacy, mask);
        assert!(child.privacy.policy_digest().is_some());
        identities.push(child.frames[0].inference.masked_digest());
        originals.push(child.frames[0].capsule.source_digest);
    }
    assert_ne!(originals[0], originals[1]);
    assert_eq!(
        identities[0], identities[1],
        "full mask reaches the model before inference"
    );
    Ok(())
}

struct DamageAfterImports {
    path: PathBuf,
    count: usize,
    fired: Cell<bool>,
}
impl HttpHistorySentinelAuthority for DamageAfterImports {
    fn permit_sentinel(
        &self,
        _: &HttpHistorySentinelPlan,
        destination: &ReferenceDeployment,
    ) -> bool {
        let complete = destination
            .ledger()
            .batches()
            .iter()
            .flat_map(|b| &b.deltas)
            .filter(|d| d.family == "file_import" && d.new_generation == 2)
            .count();
        if complete >= self.count && !self.fired.replace(true) {
            return fs::write(&self.path, b"damaged after original imports").is_ok();
        }
        true
    }
}

#[test]
fn final_verification_rejects_history_or_unsampled_destination_original_damage() -> Test {
    for history in [true, false] {
        let mut f = Fixture::new(&[response(&scene(1, 1)?), response(&scene(1, 1)?)])?;
        let scalar = ScalarExecCx::new();
        let package = package(&f, &scalar)?;
        let mut plan = plan(&f, &package, 2, false);
        plan.sampling = HttpHistorySentinelConfig {
            every_frames: 2,
            burst_frames: 2,
            max_inferences: 2,
        };
        let limits = limits(&f);
        let path = if history {
            f.source.spool().object_path(plan.history.root)
        } else {
            f.target.publisher().spool().object_path(original(&f, 1)?)
        };
        let owner = DamageAfterImports {
            path,
            count: 2,
            fired: Cell::new(false),
        };
        let result = process_http_history_sentinel(
            &f.source,
            &mut f.target,
            &package,
            PACKAGE,
            &plan,
            &limits,
            &owner,
            &f.cx,
            &scalar,
            &mut WorkBudget::new(WORK),
            &mut DecodeBudget::new(WORK),
        );
        assert!(owner.fired.get());
        if history {
            assert!(matches!(result, Err(HttpHistorySentinelError::Source(_))));
        } else {
            assert!(matches!(
                result,
                Err(HttpHistorySentinelError::Detection(_))
            ));
        }
        assert_eq!(
            f.target
                .ledger()
                .batches()
                .iter()
                .flat_map(|b| &b.deltas)
                .filter(|d| d.family == "file_import" && d.new_generation == 2)
                .count(),
            2
        );
    }
    Ok(())
}

#[test]
fn pure_plan_binds_all_choices_and_preserves_full_bursts_and_native_per_generation_limit() -> Test {
    let f = Fixture::new(&[response(&scene(1, 1)?), response(&scene(1, 1)?)])?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let mut plan = plan(&f, &package, 5, false);
    let limits = limits(&f);
    let baseline = plan.digest(&limits)?;
    for mutation in 0..4 {
        let mut changed = plan.clone();
        match mutation {
            0 => changed.bindings[0].capture_hint.start_ns = TimestampNs(11),
            1 => changed.minimum_score_ppm = Some(1),
            2 => changed.retain = true,
            _ => changed.sampling.every_frames += 1,
        }
        assert_ne!(changed.digest(&limits)?, baseline);
    }
    let mut altered = limits;
    altered.sentinel.package.h264.max_height += 16;
    assert_ne!(
        plan.digest(&altered)?,
        baseline,
        "inactive codec bounds are still approved"
    );
    altered = limits;
    altered.sentinel.package.run.execution.max_macs = u64::MAX;
    assert!(plan.reservation(&altered).is_err());
    altered = limits;
    altered.maximum_frames_per_generation = 4097;
    assert!(plan.reservation(&altered).is_err());
    plan.sampling = HttpHistorySentinelConfig {
        every_frames: 3,
        burst_frames: 2,
        max_inferences: 5,
    };
    let rows = plan.allocate(&[7, 7])?;
    assert_eq!(
        rows.iter()
            .map(|r| r.admitted_inferences)
            .collect::<Vec<_>>(),
        [2, 2]
    );
    plan.sampling.max_inferences = 1024;
    let rows = plan.allocate(&[4096, 4096])?;
    assert_eq!(
        rows.iter()
            .map(|r| r.admitted_inferences)
            .collect::<Vec<_>>(),
        [64, 64]
    );
    assert!(rows.iter().all(|r| r.budget_skipped_bursts > 0));
    assert!(plan.allocate(&[4097, 4096]).is_err());
    Ok(())
}

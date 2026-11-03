#![forbid(unsafe_code)]
//! Exact incomplete HTTP prefixes reach the trained model without inventing source completion.

#[path = "http_history_watch_contract/fixture.rs"]
mod fixture;

use std::cell::Cell;
use std::fs;
use std::path::PathBuf;

use fixture::{Fixture, Owner, SITE, Test, WORK, archive_limits, context, response, scene};
use fss_codec_mjpeg::DecodeBudget;
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_geometry::WorkBudget;
use fss_publication::NeverCancel;
use fss_reference::http_reconnect_history::VerifiedReconnectHistory;
use fss_reference::ingest::http_archive::HttpWireArchive;
use fss_reference::ingest::http_import::{HttpImportEnding, HttpImportRequest};
use fss_reference::ingest::http_prefix_sentinel::*;
use fss_reference::ingest::long_sentinel::retained::{
    LongSentinelReplayLimits, RetainedLongSentinel, rerun_long_sentinel_detection,
};
use fss_reference::ingest::long_sentinel::{LongSentinelConfig, LongSentinelLimits};
use fss_reference::ingest::privacy_mask::{
    PrivacyMaskPolicy, current_mask, declare_mask, preview_mask,
};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::{ReferenceDeployment, ScalarExecCx};

const PACKAGE: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");
const PACKAGE_DIGEST: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

impl HttpPrefixSentinelAuthority for Owner {
    fn permit_sentinel(
        &self,
        _: &HttpPrefixSentinelPlan,
        destination: &ReferenceDeployment,
    ) -> bool {
        self.0 && destination.site_lineage() == SITE
    }
}

/// Preserve N complete parts plus half the following JPEG. HTTP still declares the entire
/// original response length; neither a terminal MIME delimiter nor source EOF is passed to import.
fn incomplete(frames: usize) -> Test<Vec<u8>> {
    let images = scene(frames + 1, frames + 1)?;
    let mut wire = response(&images);
    let last = images.last().ok_or("following JPEG")?;
    let omitted = b"--camera--\r\n".len() + 2 + last.len() / 2;
    wire.truncate(
        wire.len()
            .checked_sub(omitted)
            .ok_or("partial JPEG bound")?,
    );
    Ok(wire)
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
    count: usize,
    retain: bool,
) -> Test<HttpPrefixSentinelPlan> {
    let history = VerifiedReconnectHistory::load(
        &f.source,
        f.plan.history,
        f.limits.history,
        &NeverCancel,
        &mut WorkBudget::new(WORK),
    )?;
    let boundary = history.boundaries().first().ok_or("first prefix")?;
    let binding = f.plan.bindings.first().ok_or("explicit camera binding")?;
    Ok(HttpPrefixSentinelPlan {
        import: HttpImportRequest {
            source: boundary.scope(),
            pin: boundary.prefix(),
            sensor: binding.sensor.clone(),
            stream: binding.stream.clone(),
            receive_time: binding.receive_time,
            capture_hint: Some(binding.capture_hint),
            max_frames: 200,
            max_bytes: 1024 * 1024,
        },
        acknowledged_frames: count,
        interpretation: f.plan.interpretation,
        package_digest: package.archive_digest(),
        backend: package.model().backend(),
        minimum_score_ppm: None,
        sampling: LongSentinelConfig {
            every_frames: 2,
            burst_frames: 1,
            max_inferences: 2,
        },
        retain,
    })
}
fn run(
    f: &mut Fixture,
    package: &RgbDetectorPackage,
    plan: &HttpPrefixSentinelPlan,
    limits: &LongSentinelLimits,
    scalar: &ScalarExecCx,
) -> Result<HttpPrefixSentinelReport, HttpPrefixSentinelError> {
    process_http_prefix_sentinel(
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
fn original(f: &Fixture, plan: &HttpPrefixSentinelPlan) -> Test<ContentDigest> {
    let archive = HttpWireArchive::load(
        &f.source,
        plan.import.source,
        plan.import.pin,
        archive_limits(),
        &NeverCancel,
        &mut WorkBudget::new(WORK),
    )?;
    let wire = archive.reads().next().ok_or("original read")?.1;
    Ok(ContentDigest::new(DigestAlgorithm::Sha256, wire.sha256))
}

#[test]
fn incomplete_prefix_selects_only_acknowledged_frames_and_retains_all_read_ahead() -> Test {
    let mut f = Fixture::new(&[incomplete(5)?])?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let plan = plan(&f, &package, 3, false)?;
    let limits = LongSentinelLimits::default();
    let effects = f.target.effects().last_root();
    let report = run(&mut f, &package, &plan, &limits, &scalar)?;
    assert_eq!(report.plan_digest(), plan.digest(&limits)?);
    assert_eq!(report.import().ending, HttpImportEnding::PinnedPrefix);
    assert_eq!(report.import().frames, 5);
    assert_eq!(report.acknowledged_frames(), 3);
    assert_eq!(report.imported_read_ahead_frames(), 2);
    assert_eq!(report.sentinel_report().request().segment_count, 3);
    assert_eq!(
        report
            .sentinel_report()
            .plan()
            .selected_segments()
            .into_iter()
            .collect::<Vec<_>>(),
        [0, 2]
    );
    assert_eq!(report.sentinel_report().usage().inferences, 2);
    assert!(report.sentinel_report().usage().execution_macs > 0);
    assert!(
        report
            .sentinel_report()
            .reports()
            .iter()
            .flat_map(|r| &r.frames)
            .all(|frame| frame.segment < 3)
    );
    assert!(report.retained().is_none());
    assert_eq!(report.analysis_basis(), f.target.current_anchor());
    assert_eq!(f.target.effects().last_root(), effects);
    let anchor = f.target.current_anchor().clone();
    let again = run(&mut f, &package, &plan, &limits, &scalar)?;
    assert!(again.import().reused);
    assert_eq!(
        again.sentinel_report().json(),
        report.sentinel_report().json()
    );
    assert_eq!(f.target.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn invalid_selection_authority_package_and_missing_original_refuse_before_import() -> Test {
    let mut f = Fixture::new(&[incomplete(2)?])?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let plan = plan(&f, &package, 2, false)?;
    let limits = LongSentinelLimits::default();
    let before = f.target.current_anchor().clone();
    let roots = f.target.publisher().visible_roots().count();
    for count in [0, plan.import.max_frames + 1] {
        let mut invalid = plan.clone();
        invalid.acknowledged_frames = count;
        assert!(invalid.digest(&limits).is_err());
        assert!(run(&mut f, &package, &invalid, &limits, &scalar).is_err());
    }
    let mut invalid = plan.clone();
    invalid.package_digest = ContentDigest::sha256(b"another model");
    assert!(matches!(
        run(&mut f, &package, &invalid, &limits, &scalar),
        Err(HttpPrefixSentinelError::Invalid(_))
    ));
    assert!(matches!(
        process_http_prefix_sentinel(
            &f.source,
            &mut f.target,
            &package,
            PACKAGE,
            &plan,
            &limits,
            &Owner(false),
            &f.cx,
            &scalar,
            &mut WorkBudget::new(WORK),
            &mut DecodeBudget::new(WORK)
        ),
        Err(HttpPrefixSentinelError::Denied)
    ));
    let bytes = original(&f, &plan)?;
    fs::write(
        f.source.spool().object_path(bytes),
        b"damaged original prefix",
    )?;
    f.cx.set_cancel_at_checkpoint_occurrence(STAGE_HTTP_PREFIX_SENTINEL_ANALYZE, 1);
    assert!(matches!(
        run(&mut f, &package, &plan, &limits, &scalar),
        Err(HttpPrefixSentinelError::Import(_))
    ));
    assert!(
        !f.cx.is_cancelled(),
        "missing originals refuse before model phase"
    );
    assert_eq!(f.target.current_anchor(), &before);
    assert_eq!(f.target.publisher().visible_roots().count(), roots);
    Ok(())
}

#[test]
fn read_ahead_and_acknowledged_count_bounds_fail_closed_without_model_or_retention() -> Test {
    let mut f = Fixture::new(&[incomplete(3)?])?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let mut plan = plan(&f, &package, 2, true)?;
    let limits = LongSentinelLimits::default();
    plan.import.max_frames = 2;
    let before = f.target.current_anchor().clone();
    assert!(run(&mut f, &package, &plan, &limits, &scalar).is_err());
    assert_eq!(
        f.target.current_anchor(),
        &before,
        "read-ahead is not silently discarded to fit the import bound"
    );
    plan.import.max_frames = 200;
    plan.acknowledged_frames = 4;
    f.cx.set_cancel_at_checkpoint_occurrence(STAGE_HTTP_PREFIX_SENTINEL_ANALYZE, 1);
    assert!(matches!(
        run(&mut f, &package, &plan, &limits, &scalar),
        Err(HttpPrefixSentinelError::Invalid(_))
    ));
    assert!(
        !f.cx.is_cancelled(),
        "an inflated caller count cannot reach the model"
    );
    assert!(
        f.target.current_anchor().commit_sequence > before.commit_sequence,
        "verified import remains available after selection refusal"
    );
    assert!(
        !f.target
            .ledger()
            .batches()
            .iter()
            .flat_map(|b| &b.deltas)
            .any(|d| d.family == "long_sentinel_detection")
    );
    Ok(())
}

#[test]
fn one_pixel_allowance_spans_all_bursts_and_exact_retry_reuses_the_import() -> Test {
    let mut f = Fixture::new(&[incomplete(3)?])?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let plan = plan(&f, &package, 3, false)?;
    let limits = LongSentinelLimits::default();
    let mut low = limits;
    low.maximum_pixel_samples = 96 * 48;
    assert!(run(&mut f, &package, &plan, &low, &scalar).is_err());
    let report = run(&mut f, &package, &plan, &limits, &scalar)?;
    assert!(report.import().reused);
    assert_eq!(report.sentinel_report().usage().inferences, 2);
    assert_eq!(report.sentinel_report().usage().pixel_samples, 2 * 96 * 48);
    Ok(())
}

#[test]
fn native_retention_reconciles_after_interruption_and_replays_without_the_capture_archive() -> Test
{
    let mut f = Fixture::new(&[incomplete(2)?])?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let plan = plan(&f, &package, 1, true)?;
    let limits = LongSentinelLimits::default();
    f.cx.set_cancel_at_checkpoint_occurrence(STAGE_HTTP_PREFIX_SENTINEL_RELEASE, 1);
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
    assert!(report.import().reused);
    let retained = report.retained().ok_or("retained native aggregate")?;
    assert_eq!(retained.status().as_str(), "already_retained");
    let identity = retained.report_digest();
    let root = retained.root();
    let json = report.sentinel_report().json().to_owned();
    let anchor = f.target.current_anchor().clone();
    let effects = f.target.effects().last_root();
    drop(report);
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
    let replay_limits = LongSentinelReplayLimits {
        execution: limits,
        ..Default::default()
    };
    assert_eq!(
        RetainedLongSentinel::open(&target, identity, &replay_limits, &cx)?.root(),
        root
    );
    let replay = rerun_long_sentinel_detection(
        &target,
        identity,
        &replay_limits,
        &cx,
        &ScalarExecCx::new(),
    )?;
    assert_eq!(replay.json(), json);
    assert_eq!(replay.request().segment_count, 1);
    assert_eq!(target.current_anchor(), &anchor);
    assert_eq!(target.effects().last_root(), effects);
    Ok(())
}

#[test]
fn current_privacy_reaches_every_selected_image_before_the_model() -> Test {
    let mut f = Fixture::new(&[response(&scene(3, 1)?)])?;
    let policy = PrivacyMaskPolicy::new(
        f.plan.bindings[0].sensor.clone(),
        [96, 48],
        &[[0, 0, 96, 48]],
    )?;
    let approval = preview_mask(&f.target, &policy)?.approval;
    declare_mask(&mut f.target, &policy, approval, &f.cx)?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let mut plan = plan(&f, &package, 2, false)?;
    plan.sampling.every_frames = 1;
    let report = run(
        &mut f,
        &package,
        &plan,
        &LongSentinelLimits::default(),
        &scalar,
    )?;
    let frames = report
        .sentinel_report()
        .reports()
        .iter()
        .flat_map(|report| &report.frames)
        .collect::<Vec<_>>();
    let mask = current_mask(&f.target, &plan.import.sensor)?;
    assert_eq!(frames.len(), 2);
    assert_ne!(
        frames[0].capsule.source_digest,
        frames[1].capsule.source_digest
    );
    assert_eq!(
        frames[0].inference.masked_digest(),
        frames[1].inference.masked_digest()
    );
    assert!(
        report
            .sentinel_report()
            .reports()
            .iter()
            .all(|report| report.privacy == mask)
    );
    Ok(())
}

struct DamageAfterRetention {
    path: PathBuf,
    fired: Cell<bool>,
}
impl HttpPrefixSentinelAuthority for DamageAfterRetention {
    fn permit_sentinel(
        &self,
        _: &HttpPrefixSentinelPlan,
        destination: &ReferenceDeployment,
    ) -> bool {
        let complete = destination
            .ledger()
            .batches()
            .iter()
            .flat_map(|batch| &batch.deltas)
            .any(|delta| delta.family == "long_sentinel_detection");
        if complete && !self.fired.replace(true) {
            return fs::write(
                &self.path,
                b"damaged complete original after native retention",
            )
            .is_ok();
        }
        true
    }
}

#[test]
fn final_source_and_destination_verification_covers_unsampled_read_ahead_and_tail() -> Test {
    for source in [true, false] {
        let mut f = Fixture::new(&[incomplete(3)?])?;
        let scalar = ScalarExecCx::new();
        let package = package(&f, &scalar)?;
        let plan = plan(&f, &package, 1, true)?;
        let original = original(&f, &plan)?;
        let path = if source {
            f.source.spool().object_path(original)
        } else {
            f.target.publisher().spool().object_path(original)
        };
        let owner = DamageAfterRetention {
            path,
            fired: Cell::new(false),
        };
        let result = process_http_prefix_sentinel(
            &f.source,
            &mut f.target,
            &package,
            PACKAGE,
            &plan,
            &LongSentinelLimits::default(),
            &owner,
            &f.cx,
            &scalar,
            &mut WorkBudget::new(WORK),
            &mut DecodeBudget::new(WORK),
        );
        assert!(owner.fired.get());
        assert!(
            result.is_err(),
            "no report may escape after any required original is damaged"
        );
        assert_eq!(
            f.target
                .ledger()
                .batches()
                .iter()
                .flat_map(|b| &b.deltas)
                .filter(|d| d.family == "long_sentinel_detection")
                .count(),
            1,
            "existing native custody remains explicit for recovery"
        );
    }
    Ok(())
}

#[test]
fn refused_import_progress_preserves_cold_custody_without_starting_model() -> Test {
    let mut f = Fixture::new(&[incomplete(3)?])?;
    let scalar = ScalarExecCx::new();
    let package = package(&f, &scalar)?;
    let plan = plan(&f, &package, 3, true)?;
    let limits = LongSentinelLimits::default();
    f.cx.set_cancel_at_checkpoint_occurrence(STAGE_HTTP_PREFIX_SENTINEL_ANALYZE, 1);
    let mut saved = None;
    let mut calls = 0;
    let result = process_http_prefix_sentinel_observed(
        &f.source,
        &mut f.target,
        &package,
        PACKAGE,
        &plan,
        &limits,
        &Owner(true),
        &f.cx,
        &scalar,
        &mut WorkBudget::new(WORK),
        &mut DecodeBudget::new(WORK),
        &mut |receipt| {
            calls += 1;
            saved = Some((receipt.import_identity, receipt.import_root, receipt.frames));
            false
        },
    );
    assert!(matches!(
        result,
        Err(HttpPrefixSentinelError::ProgressRefused)
    ));
    assert_eq!(calls, 1);
    assert!(
        !f.cx.is_cancelled(),
        "refused progress never enters native model phase"
    );
    assert!(
        !f.target
            .ledger()
            .batches()
            .iter()
            .flat_map(|b| &b.deltas)
            .any(|d| d.family == "long_sentinel_detection")
    );
    let (identity, root, frames) = saved.ok_or("typed durable import observation")?;
    assert_eq!(frames, 3);
    drop(f.target);
    f.cx = context(&f.target_dir.0)?;
    f.target = ReferenceDeployment::reopen(&f.target_dir.0, SITE, &f.cx)?;
    let retained = fss_reference::ingest::RetainedFileImport::open(
        &f.target,
        identity,
        limits.package.read,
        &f.cx,
    )?;
    assert_eq!(retained.import_root(), root);
    assert_eq!(retained.manifest().segment_spans.len(), frames);
    retained.verify_source(&f.target, limits.package.read, &f.cx)?;
    Ok(())
}

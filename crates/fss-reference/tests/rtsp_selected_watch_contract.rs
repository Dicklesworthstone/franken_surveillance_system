#![forbid(unsafe_code)]
//! Native selected-recording composition: custody, final-anchor analysis and refusal/retry.

#[path = "rtsp_selected_watch_contract/fixture.rs"]
mod fixture;

use std::cell::Cell;
use std::fs;

use fixture::{Fixture, Owner, SITE, Test, WORK, archive_limits, context};
use fss_geometry::WorkBudget;
use fss_publication::LocalRootPublisher;
use fss_reference::ReferenceDeployment;
use fss_reference::ingest::long_watch::LongWatchReport;
use fss_reference::ingest::rtsp_import::{MAX_ORIGINAL_BYTES, RtspImportError};
use fss_reference::ingest::rtsp_selected_watch::{
    MAX_SELECTIONS, RtspSelectedWatchAuthority, RtspSelectedWatchError, RtspSelectedWatchPlan,
    RtspWatchSelection, STAGE_RTSP_SELECTED_ANALYZE, STAGE_RTSP_SELECTED_IMPORT,
    STAGE_RTSP_SELECTED_RELEASE, process_rtsp_selections,
};

#[test]
fn native_mixed_selections_watch_every_frame_independently_at_the_final_import_anchor() -> Test {
    let mut f = Fixture::new("mixed-long", 130)?;
    let effects = f.target().effects().last_root();
    let report = f.run()?;
    assert_eq!(report.selections().len(), 4);
    assert_eq!(report.analysis_basis(), f.target().current_anchor());
    assert_eq!(report.plan_digest(), f.plan.digest(&f.limits)?);
    let expected = [
        ("window", "avc", 2, 1, 0),
        ("catalog", "avc", 260, 2, 1),
        ("pages", "avc", 6, 2, 2),
        ("window", "hevc", 4, 1, 0),
    ];
    for (selected, (kind, codec, frames, windows, pages)) in
        report.selections().iter().zip(expected)
    {
        assert_eq!(selected.selection().kind(), kind);
        assert_eq!(selected.import().codec.as_str(), codec);
        assert_eq!(selected.import().frames, frames);
        assert_eq!(selected.windows(), windows);
        assert_eq!(selected.pages(), pages);
        assert!(!selected.import().reused);
        assert_eq!(selected.watch_plan().first_segment, 0);
        assert_eq!(selected.watch_plan().segment_count, frames);
        assert_eq!(selected.watch_report().frames_decoded(), frames);
        assert_eq!(selected.request_digest(), selected.selection().digest()?);
        // Each result must equal a fresh native analysis at the final anchor. A shared tracker
        // or analysis before a later import would change its complete analysis identity.
        let fresh = LongWatchReport::analyze(
            f.target(),
            selected.watch_plan(),
            f.plan.options,
            &f.limits.watch,
            &f.cx,
        )?;
        assert_eq!(
            selected.watch_report().analysis_digest(),
            fresh.analysis_digest()
        );
        for candidate in selected.watch_report().candidates() {
            assert!(candidate.event().decision_path.abstained);
            assert!(
                f.target()
                    .current_event_authority(&candidate.event().event_id)
                    .is_err()
            );
        }
    }
    assert_eq!(f.target().effects().last_root(), effects);
    let text = report.to_json(f.target().current_anchor().commit_sequence)?;
    for claim in [
        "\"campaign_history_verified\":false",
        "\"complete_campaign\":false",
        "\"empty_attempt_coverage\":false",
        "\"tracker_continuity_across_selections\":false",
        "\"event_publication_authorized\":false",
        "\"absence_certifiable\":false",
        "\"alert_authorized\":false",
    ] {
        assert!(text.contains(claim));
    }
    assert_eq!(
        text.matches("\"independent_analysis_epoch\":true").count(),
        4
    );
    assert!(!text.contains("--approve"));
    Ok(())
}

#[test]
fn cold_exact_retry_reconciles_all_imports_without_new_authority_or_changed_analyses() -> Test {
    let mut f = Fixture::new("cold-retry", 2)?;
    let first = f.run()?;
    let basis = f.target().current_anchor().clone();
    let effects = f.target().effects().last_root();
    drop(f.target.take());
    drop(f.source.take());
    f.source = Some(LocalRootPublisher::open(
        f.directory.0.join("archive"),
        archive_limits(),
    )?);
    f.cx = context(&f.directory.0.join("destination"))?;
    f.target = Some(ReferenceDeployment::open(
        &f.directory.0.join("destination"),
        SITE,
        &f.cx,
    )?);
    let retry = f.run()?;
    assert_eq!(f.target().current_anchor(), &basis);
    assert_eq!(f.target().effects().last_root(), effects);
    for (a, b) in first.selections().iter().zip(retry.selections()) {
        assert!(b.import().reused);
        assert_eq!(a.import().import_identity, b.import().import_identity);
        assert_eq!(a.import().import_root, b.import().import_root);
        assert_eq!(
            a.watch_report().analysis_digest(),
            b.watch_report().analysis_digest()
        );
    }
    Ok(())
}

struct CountOwner(Cell<usize>);
impl RtspSelectedWatchAuthority for CountOwner {
    fn permit(&self, _: &RtspSelectedWatchPlan, _: &ReferenceDeployment) -> bool {
        self.0.set(self.0.get() + 1);
        true
    }
}

#[test]
fn complete_selection_and_decoder_admission_precede_any_import_or_authority_callback() -> Test {
    let mut f = Fixture::new("pure-admission", 2)?;
    let basis = f.target().current_anchor().clone();
    let original = f.plan.clone();
    let RtspWatchSelection::Window(last) = f.plan.selections.last_mut().ok_or("selection")? else {
        return Err("window expected".into());
    };
    last.capture_origin = None;
    let owner = CountOwner(Cell::new(0));
    let mut work = WorkBudget::new(WORK);
    let result = process_rtsp_selections(
        f.source.as_ref().ok_or("source")?,
        f.target.as_mut().ok_or("target")?,
        &f.plan,
        &f.limits,
        &owner,
        &f.cx,
        &mut work,
    );
    assert!(matches!(result, Err(RtspSelectedWatchError::Invalid(_))));
    assert_eq!(owner.0.get(), 0);
    assert_eq!(work.remaining(), WORK);
    assert_eq!(f.target().current_anchor(), &basis);
    f.plan = original;
    let first = f.plan.selections[0].clone();
    f.plan.selections.push(first.clone());
    assert!(matches!(
        f.plan.reservation(&f.limits),
        Err(RtspSelectedWatchError::Invalid(_))
    ));
    f.plan.selections = vec![first; MAX_SELECTIONS + 1];
    assert!(f.plan.reservation(&f.limits).is_err());
    f.plan.selections.truncate(1);
    f.limits.watch.decode.h265_limits.max_width = 0;
    assert!(matches!(
        f.plan.reservation(&f.limits),
        Err(RtspSelectedWatchError::Invalid(_))
    ));
    assert_eq!(f.target().current_anchor(), &basis);
    Ok(())
}

#[test]
fn order_native_pins_and_every_analysis_resource_choice_change_the_exact_plan() -> Test {
    let f = Fixture::new("plan-binding", 2)?;
    let digest = f.plan.digest(&f.limits)?;
    let mut plan = f.plan.clone();
    plan.selections.swap(0, 1);
    assert_ne!(plan.digest(&f.limits)?, digest);
    let mut plan = f.plan.clone();
    plan.screened = !plan.screened;
    assert_ne!(plan.digest(&f.limits)?, digest);
    let mut plan = f.plan.clone();
    plan.options.tolerate_decode_refusals = true;
    assert_ne!(plan.digest(&f.limits)?, digest);
    let mut limits = f.limits;
    limits.watch.maximum_source_chunk_bytes -= 1;
    assert_ne!(f.plan.digest(&limits)?, digest);
    let mut limits = f.limits;
    limits.watch.decode.h265_limits.max_pictures -= 1;
    assert_ne!(f.plan.digest(&limits)?, digest);
    let reservation = f.plan.reservation(&f.limits)?;
    assert_eq!(reservation.selections, 4);
    assert_eq!(
        reservation.source_read_bytes,
        4 * f.limits.watch.maximum_source_chunk_bytes
    );
    assert_eq!(
        reservation.pixel_samples,
        4 * f.limits.watch.maximum_pixel_samples
    );
    assert_eq!(reservation.screening_pixel_samples, 0);
    let mut screened = f.plan.clone();
    screened.screened = true;
    let screened_reservation = screened.reservation(&f.limits)?;
    assert_eq!(
        screened_reservation.screening_pixel_samples,
        4 * f.limits.watch.maximum_pixel_samples
    );
    assert_eq!(
        screened_reservation.pixel_samples,
        reservation.pixel_samples
    );
    assert_eq!(
        reservation.trace_bytes,
        4 * f.limits.watch.maximum_trace_bytes as u64
    );
    let mut limits = f.limits;
    limits.watch.decode.jpeg_work_units = u64::MAX;
    assert!(matches!(
        f.plan.reservation(&limits),
        Err(RtspSelectedWatchError::Limit)
    ));
    Ok(())
}

#[test]
fn one_shared_import_budget_cannot_be_refilled_for_later_selections() -> Test {
    let mut f = Fixture::new("shared-work", 2)?;
    let before = f.target().current_anchor().clone();
    let mut work = WorkBudget::new(2 * MAX_ORIGINAL_BYTES - 1);
    let result = process_rtsp_selections(
        f.source.as_ref().ok_or("source")?,
        f.target.as_mut().ok_or("target")?,
        &f.plan,
        &f.limits,
        &Owner(true),
        &f.cx,
        &mut work,
    );
    assert!(matches!(
        result,
        Err(RtspSelectedWatchError::Import(RtspImportError::Source(_)))
    ));
    assert!(work.remaining() < MAX_ORIGINAL_BYTES);
    assert!(f.target().current_anchor().commit_sequence > before.commit_sequence);
    let retry = f.run()?;
    assert!(retry.selections()[0].import().reused);
    assert!(retry.selections()[1..].iter().all(|s| !s.import().reused));
    Ok(())
}

#[test]
fn cancellation_at_import_analysis_and_final_release_never_returns_a_partial_report() -> Test {
    for (stage, occurrence, reused) in [
        (STAGE_RTSP_SELECTED_IMPORT, 2, 1),
        (STAGE_RTSP_SELECTED_ANALYZE, 1, 4),
        (STAGE_RTSP_SELECTED_RELEASE, 1, 4),
    ] {
        let mut f = Fixture::new(stage.rsplit(':').next().ok_or("stage")?, 2)?;
        let effects = f.target().effects().last_root();
        f.cx.set_cancel_at_checkpoint_occurrence(stage, occurrence);
        let result = process_rtsp_selections(
            f.source.as_ref().ok_or("source")?,
            f.target.as_mut().ok_or("target")?,
            &f.plan,
            &f.limits,
            &Owner(true),
            &f.cx,
            &mut WorkBudget::new(WORK),
        );
        assert!(matches!(result, Err(RtspSelectedWatchError::Denied)));
        assert!(f.cx.is_drain_completed());
        f.cx = context(&f.directory.0.join("destination"))?;
        let retry = f.run()?;
        assert_eq!(
            retry
                .selections()
                .iter()
                .filter(|s| s.import().reused)
                .count(),
            reused
        );
        assert_eq!(f.target().effects().last_root(), effects);
    }
    Ok(())
}

#[test]
fn analysis_budget_refusal_occurs_after_all_imports_and_exact_retry_reuses_them() -> Test {
    let mut f = Fixture::new("analysis-limit", 2)?;
    let normal = f.limits;
    f.limits.watch.maximum_pixel_samples = 1;
    let result = process_rtsp_selections(
        f.source.as_ref().ok_or("source")?,
        f.target.as_mut().ok_or("target")?,
        &f.plan,
        &f.limits,
        &Owner(true),
        &f.cx,
        &mut WorkBudget::new(WORK),
    );
    assert!(matches!(result, Err(RtspSelectedWatchError::Watch(_))));
    f.limits = normal;
    let retry = f.run()?;
    assert!(retry.selections().iter().all(|s| s.import().reused));
    Ok(())
}

#[test]
fn screened_native_analysis_has_a_separate_reserved_pixel_ceiling() -> Test {
    let mut f = Fixture::new("screened-limit", 2)?;
    f.plan.selections.truncate(1);
    f.plan.screened = true;
    // The native AVC fixture contains two complete 160x128 pictures. Both the foreground
    // and the independent health screen must fit their own exact cumulative allowance.
    let pixels = 2 * 160 * 128;
    f.limits.watch.maximum_pixel_samples = pixels;
    let effects = f.target().effects().last_root();
    let report = f.run()?;
    assert_eq!(report.reservation().pixel_samples, pixels);
    assert_eq!(report.reservation().screening_pixel_samples, pixels);
    let watch = report.selections()[0].watch_report();
    let health = watch.health_summary().ok_or("screening summary")?;
    assert_eq!(watch.frames_decoded(), 2);
    assert_eq!(health.frames_screened(), 2);
    assert_eq!(health.samples_screened(), pixels);
    let text = report.to_json(f.target().current_anchor().commit_sequence)?;
    assert!(text.contains(&format!("\"screening_pixel_samples\":{pixels}")));
    let basis = f.target().current_anchor().clone();
    f.limits.watch.maximum_pixel_samples -= 1;
    let result = process_rtsp_selections(
        f.source.as_ref().ok_or("source")?,
        f.target.as_mut().ok_or("target")?,
        &f.plan,
        &f.limits,
        &Owner(true),
        &f.cx,
        &mut WorkBudget::new(WORK),
    );
    assert!(matches!(result, Err(RtspSelectedWatchError::Watch(_))));
    assert_eq!(f.target().current_anchor(), &basis);
    assert_eq!(f.target().effects().last_root(), effects);
    Ok(())
}

#[test]
fn refusal_to_release_and_original_corruption_never_claim_a_reused_valid_source() -> Test {
    let mut f = Fixture::new("authority-corruption", 2)?;
    let before = f.target().current_anchor().clone();
    let mut work = WorkBudget::new(WORK);
    let denied = process_rtsp_selections(
        f.source.as_ref().ok_or("source")?,
        f.target.as_mut().ok_or("target")?,
        &f.plan,
        &f.limits,
        &Owner(false),
        &f.cx,
        &mut work,
    );
    assert!(matches!(denied, Err(RtspSelectedWatchError::Denied)));
    assert_eq!(work.remaining(), WORK);
    assert_eq!(f.target().current_anchor(), &before);
    f.run()?;
    let before = f.target().current_anchor().clone();
    let path = f
        .source
        .as_ref()
        .ok_or("source")?
        .spool()
        .object_path(f.original);
    fs::write(&path, b"corrupt original RTP")?;
    let result = process_rtsp_selections(
        f.source.as_ref().ok_or("source")?,
        f.target.as_mut().ok_or("target")?,
        &f.plan,
        &f.limits,
        &Owner(true),
        &f.cx,
        &mut WorkBudget::new(WORK),
    );
    assert!(matches!(result, Err(RtspSelectedWatchError::Import(_))));
    assert_eq!(f.target().current_anchor(), &before);
    assert_eq!(fs::read(path)?, b"corrupt original RTP");
    Ok(())
}

#![forbid(unsafe_code)]
//! Native durable reconnect histories feed restartable retained imports and whole-recording
//! proposals. Synthetic scenes test composition and refusal boundaries, not detector quality.

#[path = "http_history_watch_contract/fixture.rs"]
mod fixture;

use std::fs;

use fixture::{Fixture, Owner, SITE, Test, WORK, archive_limits, context, response, scene};
use fss_codec_mjpeg::DecodeBudget;
use fss_core::{ContentDigest, DigestAlgorithm, EventKind, EventState, TimestampNs};
use fss_geometry::WorkBudget;
use fss_publication::NeverCancel;
use fss_reference::ReferenceDeployment;
use fss_reference::http_reconnect_history::BoundaryOutcome;
use fss_reference::ingest::http_archive::HttpWireArchive;
use fss_reference::ingest::http_history_watch::{
    HttpHistoryWatchStatus, STAGE_HTTP_HISTORY_GENERATION, process_http_history,
};
use fss_reference::ingest::http_import::HttpImportError;
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};

#[test]
fn two_native_generations_find_late_entry_and_cold_retry_reuses_exact_imports_without_events()
-> Test {
    let mut fixture = Fixture::new(&[response(&scene(8, 8)?), response(&scene(200, 150)?)])?;
    let effects = fixture.target.effects().last_root();
    let report = fixture.run()?;
    assert_eq!(report.generations().len(), 2);
    let first = &report.generations()[0];
    let second = &report.generations()[1];
    assert_eq!(first.connection(), 1);
    assert_eq!(second.generation(), 2);
    assert_eq!(first.status(), HttpHistoryWatchStatus::Analyzed);
    assert_eq!(second.native_outcome(), BoundaryOutcome::NativeComplete);
    assert!(
        first
            .watch_report()
            .ok_or("first watch")?
            .candidates()
            .is_empty()
    );
    let watch = second.watch_report().ok_or("second watch")?;
    assert_eq!(watch.frames_decoded(), 200);
    assert_eq!(watch.candidates().len(), 1);
    let candidate = &watch.candidates()[0];
    assert!(candidate.entry().position() >= 150);
    assert_eq!(candidate.entry().tracker_epoch(), 0);
    assert_eq!(candidate.event().kind, EventKind::Unclassified);
    assert_eq!(candidate.event().state, EventState::Indeterminate);
    assert_eq!(candidate.event().probability.lower, 0.0);
    assert_eq!(candidate.event().probability.upper, 1.0);
    assert!(
        candidate
            .event()
            .probability
            .calibration_generation
            .is_none()
    );
    assert!(candidate.event().decision_path.abstained);
    assert!(
        candidate
            .event()
            .evidence
            .iter()
            .all(|evidence| !evidence.supports)
    );
    assert!(
        fixture
            .target
            .current_event_authority(&candidate.event().event_id)
            .is_err()
    );
    assert_eq!(fixture.target.effects().last_root(), effects);
    let proposal = candidate.proposal_digest();
    let analysis = watch.analysis_digest();
    let imports = report
        .generations()
        .iter()
        .map(|generation| {
            generation
                .import()
                .map(|receipt| (receipt.import_identity, receipt.import_root))
        })
        .collect::<Vec<_>>();
    let hints = [None, Some("fss-event watch --stream-watch".to_owned())];
    let json = report.to_json(fixture.target.current_anchor().commit_sequence, &hints)?;
    assert!(json.contains("\"tracker_continuity_across_generations\":false"));
    assert!(json.contains("\"event_publication_authorized\":false"));
    assert!(json.contains(&format!(
        "fss-event watch --stream-watch --approve {proposal}"
    )));
    assert!(report.to_json(0, &[None]).is_err());
    let before = fixture.target.current_anchor().clone();
    let Fixture {
        source_dir,
        target_dir,
        source,
        target,
        cx: _,
        plan,
        limits,
    } = fixture;
    drop(target);
    drop(source);
    let source = source_dir.open()?;
    let cx = context(&target_dir.0)?;
    let mut target = ReferenceDeployment::open(&target_dir.0, SITE, &cx)?;
    let retry = process_http_history(
        &source,
        &mut target,
        &plan,
        &limits,
        &Owner(true),
        &cx,
        &mut WorkBudget::new(WORK),
        &mut DecodeBudget::new(WORK),
    )?;
    assert_eq!(target.current_anchor(), &before);
    assert_eq!(target.effects().last_root(), effects);
    for (index, generation) in retry.generations().iter().enumerate() {
        let receipt = generation.import().ok_or("retry import")?;
        assert!(receipt.reused);
        assert_eq!(
            Some((receipt.import_identity, receipt.import_root)),
            imports[index]
        );
    }
    let watch = retry.generations()[1].watch_report().ok_or("retry watch")?;
    assert_eq!(watch.analysis_digest(), analysis);
    assert_eq!(watch.candidates()[0].proposal_digest(), proposal);
    Ok(())
}

#[test]
fn empty_failed_attempt_and_valid_incomplete_prefix_are_explicit_before_later_analysis() -> Test {
    let incomplete = b"HTTP/1.1 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=camera\r\nContent-Length: 9999\r\n\r\n--camera\r\n".to_vec();
    let mut fixture = Fixture::new(&[Vec::new(), incomplete, response(&scene(4, 4)?)])?;
    let report = fixture.run()?;
    let generations = report.generations();
    assert_eq!(generations.len(), 3);
    assert_eq!(
        generations[0].status(),
        HttpHistoryWatchStatus::EmptyResponse
    );
    assert_eq!(generations[0].prefix().bytes, 0);
    assert_eq!(
        generations[0].native_outcome(),
        BoundaryOutcome::SourceFailed
    );
    assert_eq!(
        generations[1].status(),
        HttpHistoryWatchStatus::NoCompleteJpeg
    );
    assert!(generations[1].prefix().bytes > 0);
    assert_eq!(
        generations[1].native_outcome(),
        BoundaryOutcome::SourceFailed
    );
    for generation in &generations[..2] {
        assert!(generation.import().is_none());
        assert!(generation.watch_plan().is_none());
        assert!(generation.watch_report().is_none());
    }
    assert_eq!(generations[2].status(), HttpHistoryWatchStatus::Analyzed);
    assert_eq!(
        generations[2]
            .watch_report()
            .ok_or("completed watch")?
            .frames_decoded(),
        4
    );
    let text = report.to_json(fixture.target.current_anchor().commit_sequence, &[])?;
    assert_eq!(text.matches("\"quiet_scene_proved\":false").count(), 3);
    assert!(text.contains("\"status\":\"empty_response\""));
    assert!(text.contains("\"status\":\"no_complete_jpeg\""));
    assert_eq!(
        HttpImportError::NoCompleteFrames.stable_id(),
        "ERR-HTTP-IMPORT-REQUEST-001"
    );
    Ok(())
}

#[test]
fn invalid_mapping_and_current_authority_refuse_before_any_import_mutation() -> Test {
    let mut fixture = Fixture::new(&[response(&scene(3, 3)?), response(&scene(3, 3)?)])?;
    let baseline = fixture.target.current_anchor().clone();
    let root_count = fixture.target.publisher().visible_roots().count();
    let original = fixture.plan.clone();
    fixture.plan.bindings.swap(0, 1);
    assert!(fixture.run().is_err());
    fixture.plan = original.clone();
    fixture.plan.bindings.pop();
    assert!(fixture.run().is_err());
    fixture.plan = original.clone();
    fixture.plan.bindings[1].generation = 7;
    assert!(fixture.run().is_err());
    fixture.plan = original.clone();
    fixture.plan.history.root = ContentDigest::sha256(b"not the selected durable history");
    assert!(fixture.run().is_err());
    fixture.plan = original;
    assert!(
        process_http_history(
            &fixture.source,
            &mut fixture.target,
            &fixture.plan,
            &fixture.limits,
            &Owner(false),
            &fixture.cx,
            &mut WorkBudget::new(WORK),
            &mut DecodeBudget::new(WORK)
        )
        .is_err()
    );
    assert_eq!(fixture.target.current_anchor(), &baseline);
    assert_eq!(
        fixture.target.publisher().visible_roots().count(),
        root_count
    );
    Ok(())
}

#[test]
fn interrupted_generation_reconciles_completed_import_without_a_processing_journal() -> Test {
    let mut fixture = Fixture::new(&[response(&scene(4, 4)?), response(&scene(5, 5)?)])?;
    let baseline = fixture.target.current_anchor().clone();
    fixture
        .cx
        .set_cancel_at_checkpoint_occurrence(STAGE_HTTP_HISTORY_GENERATION, 2);
    assert!(fixture.run().is_err());
    assert!(fixture.target.current_anchor().commit_sequence > baseline.commit_sequence);
    let completed_prefix = fixture.target.current_anchor().clone();
    drop(fixture.target);
    fixture.cx = context(&fixture.target_dir.0)?;
    fixture.target = ReferenceDeployment::open(&fixture.target_dir.0, SITE, &fixture.cx)?;
    assert_eq!(fixture.target.current_anchor(), &completed_prefix);
    let report = fixture.run()?;
    assert!(
        report.generations()[0]
            .import()
            .ok_or("first reconciled import")?
            .reused
    );
    assert!(
        !report.generations()[1]
            .import()
            .ok_or("second new import")?
            .reused
    );
    let complete = fixture.target.current_anchor().clone();
    let retry = fixture.run()?;
    assert!(
        retry
            .generations()
            .iter()
            .all(|generation| generation.import().is_some_and(|receipt| receipt.reused))
    );
    assert_eq!(fixture.target.current_anchor(), &complete);
    Ok(())
}

#[test]
fn damaged_copied_original_refuses_retry_while_reconstructed_jpeg_stays_intact() -> Test {
    let mut fixture = Fixture::new(&[response(&scene(6, 6)?)])?;
    let report = fixture.run()?;
    let generation = &report.generations()[0];
    let imported = generation.import().ok_or("import")?;
    let retained = RetainedFileImport::open(
        &fixture.target,
        imported.import_identity,
        RetainedReadLimits::default(),
        &fixture.cx,
    )?;
    let archive = HttpWireArchive::load(
        &fixture.source,
        generation.source(),
        generation.prefix(),
        archive_limits(),
        &NeverCancel,
        &mut WorkBudget::new(WORK),
    )?;
    let raw = archive.reads().next().ok_or("raw source")?.1;
    let digest = ContentDigest::new(DigestAlgorithm::Sha256, raw.sha256);
    let path = fixture.target.publisher().spool().object_path(digest);
    fs::write(&path, b"damaged original HTTP response")?;
    for chunk in &retained.manifest().ordered_chunks {
        assert_eq!(
            ContentDigest::sha256(&fixture.target.publisher().spool().read(*chunk)?),
            *chunk
        );
    }
    let before = fixture.target.current_anchor().clone();
    assert!(fixture.run().is_err());
    assert_eq!(fixture.target.current_anchor(), &before);
    assert_eq!(fs::read(path)?, b"damaged original HTTP response");
    Ok(())
}

#[test]
fn source_damage_or_whole_history_work_exhaustion_never_stages_a_destination_import() -> Test {
    let mut fixture = Fixture::new(&[response(&scene(4, 4)?)])?;
    let before = fixture.target.current_anchor().clone();
    assert!(
        process_http_history(
            &fixture.source,
            &mut fixture.target,
            &fixture.plan,
            &fixture.limits,
            &Owner(true),
            &fixture.cx,
            &mut WorkBudget::new(1),
            &mut DecodeBudget::new(WORK)
        )
        .is_err()
    );
    assert_eq!(fixture.target.current_anchor(), &before);
    let root = fixture
        .source
        .spool()
        .object_path(fixture.plan.history.root);
    fs::write(root, b"damaged native history root")?;
    assert!(fixture.run().is_err());
    assert_eq!(fixture.target.current_anchor(), &before);
    Ok(())
}

#[test]
fn current_privacy_masks_precede_every_generation_and_screening_suppresses_publish_hints() -> Test {
    let mut fixture = Fixture::new(&[response(&scene(12, 12)?), response(&scene(20, 3)?)])?;
    let policy = PrivacyMaskPolicy::new(
        fixture.plan.bindings[0].sensor.clone(),
        [96, 48],
        &[[0, 0, 96, 48]],
    )?;
    let approval = preview_mask(&fixture.target, &policy)?.approval;
    declare_mask(&mut fixture.target, &policy, approval, &fixture.cx)?;
    fixture.plan.screened = true;
    let report = fixture.run()?;
    for generation in report.generations() {
        let watch = generation.watch_report().ok_or("screened generation")?;
        assert!(watch.candidates().is_empty());
        assert!(watch.health_summary().is_some());
        assert!(watch.publication_blocked());
    }
    let hints = vec![Some("fss-event watch --stream-watch".to_owned()); 2];
    let text = report.to_json(fixture.target.current_anchor().commit_sequence, &hints)?;
    assert!(!text.contains("--approve"));
    // The nested sensor-health summary and its native watch envelope both carry this field.
    // Every generation's typed gate was checked above; no unblocked projection may appear.
    assert!(text.contains("\"publication_blocked\":true"));
    assert!(!text.contains("\"publication_blocked\":false"));
    Ok(())
}

#[test]
fn exact_plan_binds_timing_every_native_limit_and_checked_upfront_reservations() -> Test {
    let fixture = Fixture::new(&[response(&scene(2, 2)?), response(&scene(2, 2)?)])?;
    let baseline = fixture.plan.digest(&fixture.limits)?;
    let r = fixture.plan.reservation(&fixture.limits)?;
    assert_eq!(r.connections, 2);
    assert_eq!(r.frames, 400);
    assert_eq!(r.original_bytes, 2 * 1024 * 1024);
    assert_eq!(r.jpeg_work, 2 * fixture.limits.watch.decode.jpeg_work_units);
    assert_eq!(
        r.trace_bytes,
        2 * fixture.limits.watch.maximum_trace_bytes as u64
    );
    let mut plan = fixture.plan.clone();
    plan.bindings[0].capture_hint.start_ns = TimestampNs(11);
    assert_ne!(plan.digest(&fixture.limits)?, baseline);
    let mut limits = fixture.limits;
    limits.watch.decode.h264_limits.max_height += 16;
    assert_ne!(fixture.plan.digest(&limits)?, baseline);
    limits = fixture.limits;
    limits.watch.decode.jpeg_work_units = u64::MAX;
    assert!(fixture.plan.reservation(&limits).is_err());
    limits = fixture.limits;
    limits.maximum_frames_per_generation = 4097;
    assert!(fixture.plan.reservation(&limits).is_err());
    limits = fixture.limits;
    limits.maximum_report_bytes = 64 * 1024 * 1024;
    assert!(fixture.plan.reservation(&limits).is_err());
    Ok(())
}

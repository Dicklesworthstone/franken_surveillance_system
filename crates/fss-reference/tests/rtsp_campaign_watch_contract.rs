#![forbid(unsafe_code)]
//! Exact campaign inventory, independent native archives, preflight/custody and retry contracts.

#[path = "rtsp_campaign_watch_contract/fixture.rs"]
mod fixture;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use fixture::{Fault, Fixture, SITE, Test, WORK, archive_limits, context, digest};
use fss_geometry::WorkBudget;
use fss_publication::LocalRootPublisher;
use fss_reference::ReferenceDeployment;
use fss_reference::ingest::long_watch::LongWatchReport;
use fss_reference::ingest::rtsp_campaign_watch::*;
use fss_reference::ingest::rtsp_import::RtspImportCodec;
use fss_reference::ingest::rtsp_selected_watch::RtspWatchSelection;
use fss_reference::rtsp::campaign_history::{NativeAttemptObservation, NativeBindings};

fn tree(root: &Path) -> Test<BTreeMap<PathBuf, Vec<u8>>> {
    let mut out = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else {
                out.insert(entry.path(), fs::read(entry.path())?);
            }
        }
    }
    Ok(out)
}

#[test]
fn complete_selected_campaign_preserves_failed_empty_unknown_and_unindexed_picture_rows() -> Test {
    let mut f = Fixture::new("campaign-native", 8)?;
    let effects = f.target().effects().last_root();
    let report = f.run()?;
    assert_eq!(report.history().pin(), f.plan.history);
    assert_eq!(report.plan_digest(), f.plan.digest(&f.limits)?);
    assert_eq!(report.analysis_basis(), f.target().current_anchor());
    assert_eq!(report.attempts().len(), 4);
    assert_eq!(report.reservation().analysis.selections, 2);
    assert_eq!(report.reservation().source_verification_passes, 3);
    let expected = [(6, 2, 2, "avc"), (4, 1, 1, "hevc")];
    for (attempt, (frames, windows, pages, codec)) in report.attempts().iter().zip(expected) {
        assert_eq!(attempt.status(), RtspCampaignWatchStatus::Analyzed);
        let import = attempt.import().ok_or("import")?;
        let watch = attempt.watch_report().ok_or("watch")?;
        assert_eq!(import.frames, frames);
        assert_eq!(attempt.catalogued_pictures(), frames as u64);
        assert_eq!(attempt.decoded_pictures(), frames as u64);
        assert_eq!(import.codec.as_str(), codec);
        assert_eq!(attempt.windows(), windows);
        assert_eq!(attempt.pages(), pages);
        assert!(!import.reused);
        let fresh = LongWatchReport::analyze(
            f.target(),
            attempt.watch_plan().ok_or("watch plan")?,
            f.plan.options,
            &f.limits.watch,
            &f.cx,
        )?;
        assert_eq!(
            watch.analysis_digest(),
            fresh.analysis_digest(),
            "each attempt uses a fresh native tracker at the final import anchor"
        );
        for candidate in watch.candidates() {
            assert!(candidate.event().decision_path.abstained);
            assert!(
                f.target()
                    .current_event_authority(&candidate.event().event_id)
                    .is_err()
            );
        }
    }
    assert_eq!(report.attempts()[0].recorded_durable_pictures(), Some(8));
    assert_eq!(
        report.attempts()[0].recorded_pictures_without_catalog(),
        Some(2)
    );
    assert!(
        !report.attempts()[0]
            .recorded()
            .finish
            .as_ref()
            .ok_or("finish")?
            .native
            .as_ref()
            .ok_or("native")?
            .complete
    );
    assert_eq!(
        report.attempts()[2].status(),
        RtspCampaignWatchStatus::RecordedNoDurablePictures
    );
    assert_eq!(report.attempts()[2].recorded_durable_pictures(), Some(0));
    assert_eq!(
        report.attempts()[3].status(),
        RtspCampaignWatchStatus::StartedWithoutRetainedFinish
    );
    assert_eq!(report.attempts()[3].recorded_durable_pictures(), None);
    assert_eq!(
        report.attempts()[3].recorded_pictures_without_catalog(),
        None
    );
    assert_eq!(f.target().effects().last_root(), effects);
    let json = report.to_json(f.target().current_anchor().commit_sequence)?;
    for expected in [
        "\"campaign_history_verified\":true",
        "\"selected_attempt_inventory_complete\":true",
        "\"latest_history_verified\":false",
        "\"tracker_continuity_across_attempts\":false",
        "\"absence_certifiable\":false",
        "\"event_publication_authorized\":false",
        "\"alert_authorized\":false",
        "\"recorded_pictures_without_catalog\":2",
        "\"all_recorded_pictures_catalogued\":false",
        "\"recorded_durable_pictures\":null",
        "\"catalogued_pictures\":6",
        "\"decoded_pictures\":6",
    ] {
        assert!(json.contains(expected), "{expected}");
    }
    assert!(!json.contains("all_recorded_pictures_analyzed"));
    assert!(!json.contains("--approve"));
    Ok(())
}

#[test]
fn exact_cold_retry_reuses_all_imports_and_preserves_the_common_native_analysis_identity() -> Test {
    let mut f = Fixture::new("campaign-cold", 8)?;
    let first = f.run()?;
    let basis = f.target().current_anchor().clone();
    let paths: Vec<_> = f
        .archives
        .iter()
        .map(|archive| archive.as_ref().map(|a| a.root_dir().to_path_buf()))
        .collect();
    f.archives.clear();
    f.archives = paths
        .into_iter()
        .map(|path| {
            path.map(|p| LocalRootPublisher::open(p, archive_limits()))
                .transpose()
        })
        .collect::<Result<_, _>>()?;
    drop(f.destination.take());
    let root = f.directory.0.join("destination");
    f.cx = context(&root, false)?;
    f.history_cx = context(&f.plan.history_root, true)?;
    f.destination = Some(ReferenceDeployment::open(&root, SITE, &f.cx)?);
    let retry = f.run()?;
    assert_eq!(f.target().current_anchor(), &basis);
    for (a, b) in first.attempts().iter().zip(retry.attempts()) {
        assert_eq!(a.status(), b.status());
        if let (Some(a_import), Some(b_import)) = (a.import(), b.import()) {
            assert!(b_import.reused);
            assert_eq!(a_import.import_identity, b_import.import_identity);
            assert_eq!(a_import.import_root, b_import.import_root);
            assert_eq!(
                a.watch_report().ok_or("watch")?.analysis_digest(),
                b.watch_report().ok_or("watch")?.analysis_digest()
            );
        }
    }
    Ok(())
}

#[test]
fn a_later_corrupt_original_refuses_before_any_destination_staging_or_commit() -> Test {
    let mut f = Fixture::new("campaign-preflight", 8)?;
    let before = tree(f.target().root())?;
    let basis = f.target().current_anchor().clone();
    fs::write(&f.source_objects[1], b"corrupt later original HEVC RTP")?;
    assert!(matches!(f.run(), Err(RtspCampaignWatchError::Import(_))));
    assert_eq!(f.target().current_anchor(), &basis);
    assert_eq!(tree(f.target().root())?, before);
    Ok(())
}

#[test]
fn pure_mapping_rejects_wrong_codec_scope_clocks_order_omission_and_extra_bindings() -> Test {
    let f = Fixture::new("campaign-mapping", 8)?;
    let history = f.inspect()?;
    f.plan.validate_history(&history)?;
    for mutation in 0..9 {
        let mut plan = f.plan.clone();
        let Some(RtspWatchSelection::Pages(request)) = &mut plan.bindings[0].selection else {
            return Err("pages".into());
        };
        match mutation {
            0 => request.codec = RtspImportCodec::Hevc,
            1 => request.scope.recording.anchor = digest("wrong authority anchor"),
            2 => request.scope.recording.receive_clock = digest("wrong receive clock"),
            3 => request.scope.decode_clock = digest("wrong decode clock"),
            4 => request.scope.time_scale += 1,
            5 => request.pages.swap(0, 1),
            6 => {
                request.pages.pop();
            }
            7 => {
                plan.bindings[0].selection = None;
            }
            _ => {
                plan.bindings.pop();
            }
        }
        assert!(
            plan.validate_history(&history).is_err(),
            "mutation {mutation}"
        );
    }
    let mut plan = f.plan.clone();
    plan.bindings[3].selection = plan.bindings[0].selection.clone();
    assert!(
        plan.validate_history(&history).is_err(),
        "unknown attempt cannot borrow another catalog"
    );
    assert!(
        f.plan
            .validate_destination(&history, Path::new(&history.plan().attempts[3].pins_path))
            .is_err()
    );
    for destination in [
        Path::new("relative/destination"),
        Path::new("/"),
        Path::new("/tmp/source/../destination"),
    ] {
        assert!(f.plan.validate_destination(&history, destination).is_err());
    }
    Ok(())
}

#[test]
fn verified_catalog_samples_cannot_exceed_the_recorded_native_count() -> Test {
    let mut f = Fixture::new("campaign-count", 5)?;
    let before = tree(f.target().root())?;
    assert!(matches!(
        f.run(),
        Err(RtspCampaignWatchError::Invalid(
            "verified catalog exceeds recorded durable picture count"
        ))
    ));
    assert_eq!(tree(f.target().root())?, before);
    Ok(())
}

#[test]
fn exact_start_only_prefix_stays_unknown_despite_later_retained_activity_and_needs_no_archive()
-> Test {
    let mut f = Fixture::new("campaign-prefix", 8)?;
    f.plan.history = f.first_start;
    f.plan.bindings.truncate(1);
    f.plan.bindings[0].selection = None;
    f.archives = vec![None];
    // Later complete catalogs exist, but this selected prefix grants no permission to discover them.
    fs::write(&f.source_objects[0], b"unselected broken catalog")?;
    let basis = f.target().current_anchor().clone();
    let report = f.run()?;
    assert_eq!(report.attempts().len(), 1);
    assert_eq!(report.reservation().analysis.selections, 0);
    assert_eq!(report.reservation().analysis.frames, 0);
    assert_eq!(
        report.attempts()[0].status(),
        RtspCampaignWatchStatus::StartedWithoutRetainedFinish
    );
    assert!(report.attempts()[0].import().is_none());
    assert!(report.attempts()[0].recorded_durable_pictures().is_none());
    assert_eq!(f.target().current_anchor(), &basis);
    Ok(())
}

#[test]
fn all_unknown_analysis_still_validates_decode_limits_before_authority_or_work() -> Test {
    let mut f = Fixture::new("campaign-empty-limits", 8)?;
    f.plan.history = f.first_start;
    f.plan.bindings.truncate(1);
    f.plan.bindings[0].selection = None;
    f.archives = vec![None];
    f.limits.watch.decode.jpeg_work_units = 0;
    let calls = f.owner.calls.load(Ordering::Acquire);
    let mut work = WorkBudget::new(WORK);
    let result = process_rtsp_campaign(
        &[None],
        f.destination.as_mut().ok_or("target")?,
        &f.plan,
        &f.limits,
        &f.owner,
        &f.history_cx,
        &f.cx,
        &mut work,
    );
    assert!(matches!(result, Err(RtspCampaignWatchError::Selection(_))));
    assert_eq!(f.owner.calls.load(Ordering::Acquire), calls);
    assert_eq!(work.remaining(), WORK);
    Ok(())
}

#[test]
fn unavailable_native_observations_and_unindexed_pictures_are_not_empty_attempts() -> Test {
    for pictures in [None, Some(3_u64)] {
        let mut f = Fixture::new(
            if pictures.is_some() {
                "campaign-unindexed"
            } else {
                "campaign-unavailable"
            },
            8,
        )?;
        let native = pictures.map(|count| NativeAttemptObservation {
            complete: false,
            error_id: Some("ERR-CAPTURE-RTSP-SOURCE-001".into()),
            retry: None,
            durable_pictures: count,
            recovery_required: true,
            bindings: NativeBindings::default(),
        });
        f.finish_fourth(native)?;
        let report = f.run()?;
        let last = &report.attempts()[3];
        assert_eq!(
            last.status(),
            if pictures.is_some() {
                RtspCampaignWatchStatus::RecordedPicturesWithoutCatalog
            } else {
                RtspCampaignWatchStatus::NativeObservationUnavailable
            }
        );
        assert_eq!(last.recorded_durable_pictures(), pictures);
        assert_eq!(last.recorded_pictures_without_catalog(), pictures);
        assert_eq!(last.catalogued_pictures(), 0);
        assert!(last.import().is_none());
        assert!(!Path::new(&last.recorded().attempt.archive_path).exists());
    }
    Ok(())
}

#[test]
fn cancellation_at_each_phase_never_returns_a_partial_report_and_retry_reconciles_imports() -> Test
{
    for (stage, occurrence, reused) in [
        (STAGE_RTSP_CAMPAIGN_PREFLIGHT, 2, 0),
        (STAGE_RTSP_CAMPAIGN_IMPORT, 2, 1),
        (STAGE_RTSP_CAMPAIGN_ANALYZE, 1, 2),
        (STAGE_RTSP_CAMPAIGN_REVALIDATE, 1, 2),
        (STAGE_RTSP_CAMPAIGN_RELEASE, 1, 2),
    ] {
        let mut f = Fixture::new(stage.rsplit(':').next().ok_or("stage")?, 8)?;
        f.cx.set_cancel_at_checkpoint_occurrence(stage, occurrence);
        assert!(matches!(f.run(), Err(RtspCampaignWatchError::Denied)));
        assert!(f.cx.is_drain_completed());
        f.cx = context(&f.directory.0.join("destination"), false)?;
        let retry = f.run()?;
        assert_eq!(
            retry
                .attempts()
                .iter()
                .filter_map(|a| a.import())
                .filter(|i| i.reused)
                .count(),
            reused
        );
    }
    Ok(())
}

#[test]
fn shared_work_refusal_and_revoked_authority_precede_any_import() -> Test {
    let mut f = Fixture::new("campaign-work", 8)?;
    let basis = f.target().current_anchor().clone();
    let sources: Vec<_> = f.archives.iter().map(Option::as_ref).collect();
    let result = process_rtsp_campaign(
        &sources,
        f.destination.as_mut().ok_or("target")?,
        &f.plan,
        &f.limits,
        &f.owner,
        &f.history_cx,
        &f.cx,
        &mut WorkBudget::new(1),
    );
    assert!(result.is_err());
    assert_eq!(f.target().current_anchor(), &basis);
    f.owner.enabled.store(false, Ordering::Release);
    let mut work = WorkBudget::new(WORK);
    let result = process_rtsp_campaign(
        &sources,
        f.destination.as_mut().ok_or("target")?,
        &f.plan,
        &f.limits,
        &f.owner,
        &f.history_cx,
        &f.cx,
        &mut work,
    );
    assert!(matches!(result, Err(RtspCampaignWatchError::Denied)));
    assert_eq!(work.remaining(), WORK);
    assert_eq!(f.target().current_anchor(), &basis);
    Ok(())
}

#[test]
fn analysis_and_complete_report_limits_preserve_completed_imports_for_exact_retry() -> Test {
    for report_limit in [false, true] {
        let mut f = Fixture::new(
            if report_limit {
                "campaign-report-limit"
            } else {
                "campaign-analysis-limit"
            },
            8,
        )?;
        let original = f.limits;
        if report_limit {
            f.limits.maximum_report_bytes = 1;
        } else {
            f.limits.watch.maximum_pixel_samples = 1;
        }
        assert!(f.run().is_err());
        f.limits = original;
        let retry = f.run()?;
        assert!(
            retry
                .attempts()
                .iter()
                .filter_map(|a| a.import())
                .all(|i| i.reused)
        );
    }
    Ok(())
}

#[test]
fn final_source_and_history_revalidation_refuse_damage_after_successful_import_publication() -> Test
{
    for fault_kind in ["original", "history-change", "history-missing"] {
        let mut f = Fixture::new(fault_kind, 8)?;
        let path = if fault_kind == "original" {
            f.source_objects[0].clone()
        } else {
            f.history_object.clone()
        };
        let bytes = fs::read(&path)?;
        let sequence = f.target().current_anchor().commit_sequence;
        *f.owner.fault.lock().map_err(|_| "fault lock")? = Some(Fault {
            after_sequence: sequence,
            path: path.clone(),
            bytes: if fault_kind == "history-missing" {
                None
            } else {
                Some(b"changed after initial complete source preflight".to_vec())
            },
        });
        let result = f.run();
        assert!(
            matches!(
                result,
                Err(RtspCampaignWatchError::Import(_)) | Err(RtspCampaignWatchError::History(_))
            ),
            "{fault_kind}: {result:?}"
        );
        assert!(f.target().current_anchor().commit_sequence > sequence);
        fs::write(path, bytes)?;
        let retry = f.run()?;
        assert_eq!(
            retry
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

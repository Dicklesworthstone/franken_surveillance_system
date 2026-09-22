#![forbid(unsafe_code)]
//! Historical recipes stay exact as source custody continues growing.
mod historical_recipe_support;
use historical_recipe_support::*;
use fss_core::ContentDigest;
use fss_publication::{NeverCancel, PublishOutcome};
use fss_reference::rtsp::datagram_reconstruction::recording::{DatagramRecordingReplay, RecordingReplayStep};
use fss_reference::rtsp::recording_capture::CapturePoll;
use fss_reference::rtsp::recording_collector::RecordingTiming;
use fss_reference::rtsp::recording_recipe::{RecordingRecipe, RecordingTimingDecision};
use fss_reference::rtsp::recording_recipe::storage::PreparedRecordingRecipe;
use fss_reference::rtsp::recording_recipe::storage::operation::*;

#[test]
fn continued_capture_does_not_change_old_recordings_result_identity_or_selected_counts() -> Test {
    let f = seed("historical-exact", 3, false, false)?;
    let mut p = open(&f.path)?;
    let before = load(&f, &p)?;
    let expected = PreparedReconstruction::prepare(&before, &p, bounds(), ReconstructionLimits::default(),
        &Clock(1000), &NeverCancel, &mut work())?;
    let current_head = append_tail(&mut p)?;
    let after = load(&f, &p)?;
    assert_eq!(after.pin(), &f.pin);
    assert_eq!(after.observed_source_head(), current_head);
    let actual = PreparedReconstruction::prepare(&after, &p, bounds(), ReconstructionLimits::default(),
        &Clock(9000), &NeverCancel, &mut work())?;
    assert_eq!(actual.pin(), expected.pin()); assert_eq!(actual.summary(), expected.summary());
    assert_eq!(actual.summary().rtcp_observations, 0);
    assert_eq!(actual.summary().rtp_observations, f.pin.source.datagrams);
    for (a, b) in actual.windows().iter().zip(expected.windows()) {
        assert_eq!(a.manifest(), b.manifest()); assert_eq!(a.objects().source, b.objects().source);
        assert_eq!(a.objects().media, b.objects().media); assert_eq!(a.objects().index, b.objects().index);
    }
    actual.publish(&mut p, u64::MAX, &Clock(9000), &NeverCancel, &mut work())?;
    assert_eq!(current(&p)?.pin(), current_head);
    Ok(())
}

#[test]
fn lost_publication_reply_then_new_capture_then_cold_retry_reuses_original_roots() -> Test {
    let f = seed("historical-retry", 2, false, false)?;
    let first = {
        let mut p = open(&f.path)?; let loaded = load(&f, &p)?;
        let plan = PreparedReconstruction::prepare(&loaded, &p, bounds(), ReconstructionLimits::default(),
            &Clock(1000), &NeverCancel, &mut work())?;
        let pin = plan.publish(&mut p, u64::MAX, &Clock(1000), &NeverCancel, &mut work())?.pin;
        append_tail(&mut p)?; pin
    };
    let mut p = open(&f.path)?; let head = current(&p)?.pin(); let loaded = load(&f, &p)?;
    let plan = PreparedReconstruction::prepare(&loaded, &p, bounds(), ReconstructionLimits::default(),
        &Clock(7000), &NeverCancel, &mut work())?;
    assert_eq!(plan.pin(), &first);
    let before = p.visible_roots().count();
    let retry = plan.publish(&mut p, u64::MAX, &Clock(7000), &NeverCancel, &mut work())?;
    assert_eq!(retry.completion.outcome, PublishOutcome::AlreadyPublished);
    assert!(retry.windows.iter().all(|r| r.outcome == PublishOutcome::AlreadyPublished));
    assert_eq!(p.visible_roots().count(), before); assert_eq!(current(&p)?.pin(), head);
    Ok(())
}

#[test]
fn growth_between_loading_preparation_and_publication_never_retargets_the_input() -> Test {
    let f = seed("historical-between-steps", 1, false, false)?;
    let mut p = open(&f.path)?; let loaded = load(&f, &p)?;
    append_tail(&mut p)?;
    let plan = PreparedReconstruction::prepare(&loaded, &p, bounds(), ReconstructionLimits::default(),
        &Clock(1000), &NeverCancel, &mut work())?;
    let head = append_tail(&mut p)?;
    let result = plan.publish(&mut p, u64::MAX, &Clock(2000), &NeverCancel, &mut work())?;
    assert_eq!(plan.recipe_pin().source, f.pin.source);
    assert_eq!(loaded.observed_source_head(), f.pin.source);
    assert_eq!(plan.summary().rtcp_observations, 0);
    assert_eq!(result.windows.len(), f.expected.len()); assert_eq!(current(&p)?.pin(), head);
    Ok(())
}

#[test]
fn later_fragment_completion_does_not_repair_an_older_incomplete_recipe() -> Test {
    let f = seed("historical-fragment", 0, false, true)?;
    let mut p = open(&f.path)?; let loaded = load(&f, &p)?;
    let expected = PreparedReconstruction::prepare(&loaded, &p, bounds(), ReconstructionLimits::default(),
        &Clock(1000), &NeverCancel, &mut work())?;
    let nals = source::nals();
    let idr = *nals.iter().find(|n| n[0] & 31 == 5).ok_or("missing IDR")?;
    let mut payload = vec![(idr[0] & 0x60) | 28, (idr[0] & 31) | 64];
    payload.extend_from_slice(&idr[1 + (idr.len() - 1) / 2..]);
    let mut packet = source::packet(3, 9000, &payload); packet[1] |= 128;
    let head = append_source(&mut p, 0, &packet)?;
    let historical = load(&f, &p)?;
    let actual = PreparedReconstruction::prepare(&historical, &p, bounds(), ReconstructionLimits::default(),
        &Clock(2000), &NeverCancel, &mut work())?;
    assert_eq!(actual.pin(), expected.pin()); assert_eq!(actual.summary(), expected.summary());
    assert!(actual.windows().is_empty()); assert!(actual.summary().fragment_bytes > 0);
    assert_eq!(historical.observed_source_head(), head);
    Ok(())
}

#[test]
fn old_and_new_recipes_over_one_growing_camera_chain_remain_independently_replayable() -> Test {
    let f = seed("historical-multiple-recipes", 1, false, false)?;
    let mut p = open(&f.path)?; let old = load(&f, &p)?;
    let nals = source::nals();
    let idr = *nals.iter().find(|n| n[0] & 31 == 5).ok_or("missing IDR")?;
    let mut packet = source::packet(3, 12600, idr); packet[1] |= 128;
    append_source(&mut p, 0, &packet)?;
    let all = current(&p)?;
    let avc = old.recipe().avc_spec(); let recording = old.recipe().recording_spec().clone();
    let mut replay = DatagramRecordingReplay::new(&all, avc, recording.clone(), bounds(), 1000)?;
    let mut decisions = Vec::new(); let mut finished = false;
    for _ in 0..256 {
        match replay.step(&p, 1000, &NeverCancel, &mut work())? {
            RecordingReplayStep::Capture(CapturePoll::TimingRequired(picture)) => {
                let timing = RecordingTiming { decode_time: 700 + decisions.len() as u64 * 3600,
                    duration: 3600, composition_offset: -25 };
                decisions.push(RecordingTimingDecision { observations_read: replay.observations_read(), picture, timing });
                replay.supply_timing(timing, 1000, &NeverCancel, &mut work())?;
            }
            RecordingReplayStep::PrefixReady { .. } => replay.finish_prefix(1000, &NeverCancel, &mut work())?,
            RecordingReplayStep::FinishedPrefix { .. } => { finished = true; break; },
            RecordingReplayStep::Stopped { .. } | RecordingReplayStep::Ended => return Err("extended replay stopped".into()),
            _ => {},
        }
    }
    assert!(finished); assert_eq!(decisions.len(), 2);
    let recipe = RecordingRecipe::new(&all, avc, recording, decisions, limits().recipe)?;
    let new_pin = PreparedRecordingRecipe::prepare(&recipe, &all, &p, limits().storage, &NeverCancel, &mut work())?
        .publish(&mut p, &NeverCancel, &mut work())?.pin;
    let newer = LoadedRecordingRecipe::load(&p, RecipeSelection { recipe: new_pin.recipe,
        root: new_pin.root, scope: source_scope()? }, limits(), &NeverCancel, &mut work())?;
    let historical = load(&f, &p)?;
    let old_plan = PreparedReconstruction::prepare(&historical, &p, bounds(), ReconstructionLimits::default(),
        &Clock(1000), &NeverCancel, &mut work())?;
    let new_plan = PreparedReconstruction::prepare(&newer, &p, bounds(), ReconstructionLimits::default(),
        &Clock(1000), &NeverCancel, &mut work())?;
    assert_eq!(old_plan.summary().timings_applied, 1); assert_eq!(new_plan.summary().timings_applied, 2);
    assert_ne!(old_plan.pin(), new_plan.pin());
    assert_eq!(old_plan.windows()[0].manifest().root(), f.expected[0]);
    old_plan.publish(&mut p, u64::MAX, &Clock(1000), &NeverCancel, &mut work())?;
    new_plan.publish(&mut p, u64::MAX, &Clock(1000), &NeverCancel, &mut work())?;
    assert_eq!(current(&p)?.pin(), all.pin());
    Ok(())
}

#[test]
fn corrupt_descendant_after_preparation_blocks_every_output_write() -> Test {
    let f = seed("historical-corrupt-tail", 1, false, false)?;
    let mut p = open(&f.path)?; append_tail(&mut p)?; let loaded = load(&f, &p)?;
    let plan = PreparedReconstruction::prepare(&loaded, &p, bounds(), ReconstructionLimits::default(),
        &Clock(1000), &NeverCancel, &mut work())?;
    let digest = ContentDigest::sha256(&[0, 0, 0]).to_text();
    std::fs::write(f.path.join("spool/objects").join(digest.strip_prefix("sha256:").ok_or("digest")?), b"bad envelope")?;
    let failure = plan.publish(&mut p, u64::MAX, &Clock(2000), &NeverCancel, &mut work())
        .err().ok_or("ignored corrupt descendant")?;
    assert!(failure.windows.is_empty()); assert!(p.root(&plan.window_slot(0)?).is_none());
    assert!(p.root(&plan.pin().slot).is_none());
    Ok(())
}

#[test]
fn full_namespace_bounds_and_observed_head_rollback_are_not_bypassed_by_old_recipe() -> Test {
    let f = seed("historical-bounds-rollback", 1, false, false)?;
    let mut p = open(&f.path)?; let head = append_tail(&mut p)?;
    let mut ceiling = limits(); ceiling.source.max_datagrams = f.pin.source.datagrams as usize;
    assert!(LoadedRecordingRecipe::load(&p, select(&f)?, ceiling, &NeverCancel, &mut work()).is_err());
    let loaded = load(&f, &p)?;
    let plan = PreparedReconstruction::prepare(&loaded, &p, bounds(), ReconstructionLimits::default(),
        &Clock(1000), &NeverCancel, &mut work())?;
    let slot = p.visible_roots().find(|r| r.root == head.head).ok_or("tail root missing")?.slot.clone();
    let root_file = p.root_dir().join("roots").join(format!("{slot}.root"));
    drop(p); std::fs::remove_file(root_file)?; let mut p = open(&f.path)?;
    let failure = plan.publish(&mut p, u64::MAX, &Clock(1000), &NeverCancel, &mut work())
        .err().ok_or("forgot later observed head")?;
    assert!(failure.windows.is_empty()); assert!(p.root(&plan.pin().slot).is_none());
    Ok(())
}

#[test]
fn late_timing_mismatch_still_returns_unpublished_windows_when_history_grows() -> Test {
    let f = seed("historical-late-mismatch", 3, true, false)?;
    let mut p = open(&f.path)?; append_tail(&mut p)?; let loaded = load(&f, &p)?;
    let before = p.visible_roots().count();
    let failure = PreparedReconstruction::prepare(&loaded, &p, bounds(), ReconstructionLimits::default(),
        &Clock(1000), &NeverCancel, &mut work()).err().ok_or("wrong timing accepted")?;
    assert!(!failure.windows.is_empty()); assert_eq!(p.visible_roots().count(), before);
    Ok(())
}

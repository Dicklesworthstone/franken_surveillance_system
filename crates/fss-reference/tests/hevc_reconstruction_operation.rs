#![forbid(unsafe_code)]
//! Whole-recipe reconstruction: prepare without writes, publish once, reuse roots, and retain refusals.
#[path = "hevc_recipe_support/mod.rs"]
mod fixture;
use fixture::*;
use fss_core::ContentDigest;
use fss_publication::{
    NeverCancel, PublishCancellation, PublishCutPoint, PublishOutcome, SlotName,
};
use fss_reference::rtsp::recording::hevc::local::load_hevc_recording;
use fss_reference::rtsp::recording_recipe::hevc::storage::operation::*;

#[test]
fn whole_native_program_prepares_without_writes_then_commits_one_complete_result() -> Test {
    let f = seed("cold", 3, false, false)?;
    let mut p = open(&f.path)?;
    let loaded = load(&f, &p)?;
    let before = p.visible_roots().count();
    let plan = PreparedReconstruction::prepare(
        &loaded,
        &p,
        bounds(),
        ReconstructionLimits::default(),
        &Clock(1000),
        &NeverCancel,
        &mut work(),
    )?;
    assert_eq!(p.visible_roots().count(), before);
    assert_eq!(
        plan.windows()
            .iter()
            .map(|w| w.manifest().root())
            .collect::<Vec<_>>(),
        f.expected
    );
    assert_eq!(plan.summary().timings_applied, 3);
    assert!(p.root(&plan.pin().slot).is_none());
    let published = plan.publish(&mut p, u64::MAX, &Clock(2000), &NeverCancel, &mut work())?;
    assert_eq!(published.windows.len(), f.expected.len());
    assert_eq!(published.completion.root, plan.pin().root);
    assert_eq!(p.visible_roots().count(), before + f.expected.len() + 1);
    for (index, root) in f.expected.iter().enumerate() {
        let w = load_hevc_recording(
            &p,
            &plan.window_slot(index)?,
            *root,
            &loaded.recipe().recording_spec().scope,
            &NeverCancel,
        )?;
        assert_eq!(w.objects().source, plan.windows()[index].objects().source);
    }
    Ok(())
}

#[test]
fn second_process_equivalent_load_and_repeat_publication_reuses_every_root() -> Test {
    let f = seed("retry", 2, false, false)?;
    let first = {
        let mut p = open(&f.path)?;
        let loaded = load(&f, &p)?;
        let plan = PreparedReconstruction::prepare(
            &loaded,
            &p,
            bounds(),
            ReconstructionLimits::default(),
            &Clock(1000),
            &NeverCancel,
            &mut work(),
        )?;
        plan.publish(&mut p, u64::MAX, &Clock(1000), &NeverCancel, &mut work())?
            .pin
    };
    let mut p = open(&f.path)?;
    let loaded = load(&f, &p)?;
    let plan = PreparedReconstruction::prepare(
        &loaded,
        &p,
        bounds(),
        ReconstructionLimits::default(),
        &Clock(9_000_000_000),
        &NeverCancel,
        &mut work(),
    )?;
    assert_eq!(plan.pin(), &first);
    let count = p.visible_roots().count();
    let again = plan.publish(
        &mut p,
        u64::MAX,
        &Clock(9_000_000_000),
        &NeverCancel,
        &mut work(),
    )?;
    assert!(
        again
            .windows
            .iter()
            .all(|r| r.outcome == PublishOutcome::AlreadyPublished)
    );
    assert_eq!(again.completion.outcome, PublishOutcome::AlreadyPublished);
    assert_eq!(p.visible_roots().count(), count);
    Ok(())
}

#[test]
fn late_timing_mismatch_returns_prior_windows_without_publishing_any_of_them() -> Test {
    let f = seed("late-mismatch", 3, true, false)?;
    let p = open(&f.path)?;
    let loaded = load(&f, &p)?;
    let count = p.visible_roots().count();
    let error = PreparedReconstruction::prepare(
        &loaded,
        &p,
        bounds(),
        ReconstructionLimits::default(),
        &Clock(1000),
        &NeverCancel,
        &mut work(),
    )
    .err()
    .ok_or("wrong program was accepted")?;
    assert!(matches!(error.reason, ReconstructionError::Replay(_)));
    assert!(!error.windows.is_empty());
    assert_eq!(p.visible_roots().count(), count);
    Ok(())
}

#[test]
fn incomplete_fragment_produces_zero_windows_and_explicit_nonzero_remainder() -> Test {
    let f = seed("fragment", 0, false, true)?;
    let mut p = open(&f.path)?;
    let loaded = load(&f, &p)?;
    let plan = PreparedReconstruction::prepare(
        &loaded,
        &p,
        bounds(),
        ReconstructionLimits::default(),
        &Clock(1000),
        &NeverCancel,
        &mut work(),
    )?;
    assert!(plan.windows().is_empty());
    assert!(plan.summary().fragment_bytes > 0);
    assert!(plan.retained().held_source.is_some());
    let published = plan.publish(&mut p, u64::MAX, &Clock(1000), &NeverCancel, &mut work())?;
    assert!(published.windows.is_empty());
    assert_eq!(published.completion.root, plan.pin().root);
    Ok(())
}

#[test]
fn output_byte_and_window_caps_preserve_the_refused_window() -> Test {
    let f = seed("output-cap", 3, false, false)?;
    let p = open(&f.path)?;
    let loaded = load(&f, &p)?;
    let before = p.visible_roots().count();
    for limits in [
        ReconstructionLimits {
            max_output_bytes: 1,
            ..ReconstructionLimits::default()
        },
        ReconstructionLimits {
            max_windows: 1,
            ..ReconstructionLimits::default()
        },
    ] {
        let error = PreparedReconstruction::prepare(
            &loaded,
            &p,
            bounds(),
            limits,
            &Clock(1000),
            &NeverCancel,
            &mut work(),
        )
        .err()
        .ok_or("ignored output bound")?;
        assert!(matches!(error.reason, ReconstructionError::Limit));
        assert!(error.withheld.is_some());
        assert_eq!(p.visible_roots().count(), before);
    }
    Ok(())
}

#[test]
fn source_scope_recipe_identity_and_component_ceilings_are_independent() -> Test {
    let f = seed("scope", 1, false, false)?;
    let p = open(&f.path)?;
    let mut changed = select(&f)?;
    changed.scope.receive_clock = ContentDigest::sha256(b"wrong clock");
    assert!(LoadedRecordingRecipe::load(&p, changed, limits(), &NeverCancel, &mut work()).is_err());
    let mut changed = select(&f)?;
    changed.recipe = ContentDigest::sha256(b"wrong recipe");
    assert!(LoadedRecordingRecipe::load(&p, changed, limits(), &NeverCancel, &mut work()).is_err());
    let mut lower = limits();
    lower.recipe.reorder.max_bytes -= 1;
    assert!(
        LoadedRecordingRecipe::load(&p, select(&f)?, lower, &NeverCancel, &mut work()).is_err()
    );
    Ok(())
}
struct Stop;
impl PublishCancellation for Stop {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        true
    }
}
#[test]
fn cancellation_deadline_and_work_refuse_without_any_output_root() -> Test {
    let f = seed("bounds", 1, false, false)?;
    let p = open(&f.path)?;
    let loaded = load(&f, &p)?;
    let before = p.visible_roots().count();
    assert!(
        PreparedReconstruction::prepare(
            &loaded,
            &p,
            bounds(),
            ReconstructionLimits::default(),
            &Clock(1000),
            &Stop,
            &mut work()
        )
        .is_err()
    );
    assert!(
        PreparedReconstruction::prepare(
            &loaded,
            &p,
            bounds(),
            ReconstructionLimits::default(),
            &Clock(1000),
            &NeverCancel,
            &mut WorkBudget::new(0)
        )
        .is_err()
    );
    let mut expired = bounds();
    expired.deadline_ns = 1000;
    assert!(
        PreparedReconstruction::prepare(
            &loaded,
            &p,
            expired,
            ReconstructionLimits::default(),
            &Clock(1000),
            &NeverCancel,
            &mut work()
        )
        .is_err()
    );
    assert_eq!(p.visible_roots().count(), before);
    Ok(())
}

#[test]
fn unexpected_output_slot_is_refused_before_creating_an_expected_window() -> Test {
    let f = seed("conflict", 1, false, false)?;
    let mut p = open(&f.path)?;
    let loaded = load(&f, &p)?;
    let plan = PreparedReconstruction::prepare(
        &loaded,
        &p,
        bounds(),
        ReconstructionLimits::default(),
        &Clock(1000),
        &NeverCancel,
        &mut work(),
    )?;
    let name = plan.pin().slot.as_str().replace("complete", "wffffffff");
    let metadata = p.stage_object(b"unaccounted reconstruction")?;
    let foreign = fss_object::ObjectManifest::new("foreign", [], Some(metadata))?;
    p.publish_cancellable(&SlotName::parse(&name)?, &foreign, &NeverCancel)?;
    assert!(
        plan.publish(&mut p, u64::MAX, &Clock(1000), &NeverCancel, &mut work())
            .is_err()
    );
    assert!(p.root(&plan.window_slot(0)?).is_none());
    assert!(p.root(&plan.pin().slot).is_none());
    Ok(())
}

#[test]
fn every_window_root_crash_cut_leaves_completion_absent_and_plan_unchanged() -> Test {
    for cut in [
        PublishCutPoint::AfterChildrenVerified,
        PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite,
        PublishCutPoint::AfterRootRename,
    ] {
        let f = seed("window-cuts", 1, false, false)?;
        let mut p = open(&f.path)?;
        let loaded = load(&f, &p)?;
        let plan = PreparedReconstruction::prepare(
            &loaded,
            &p,
            bounds(),
            ReconstructionLimits::default(),
            &Clock(1000),
            &NeverCancel,
            &mut work(),
        )?;
        let candidate = plan.pin().clone();
        p.inject_crash_at(cut);
        let error = plan
            .publish(&mut p, u64::MAX, &Clock(1000), &NeverCancel, &mut work())
            .err()
            .ok_or("crash passed")?;
        assert!(error.windows.is_empty());
        assert_eq!(plan.pin(), &candidate);
        drop(p);
        let mut p = open(&f.path)?;
        assert!(p.root(&candidate.slot).is_none());
        if cut == PublishCutPoint::AfterRootRename {
            let result = plan.publish(&mut p, u64::MAX, &Clock(1000), &NeverCancel, &mut work())?;
            assert_eq!(result.windows[0].outcome, PublishOutcome::AlreadyPublished);
        }
    }
    Ok(())
}

#[test]
fn complete_root_lost_ack_retries_without_reconstructing_a_duplicate_window() -> Test {
    let f = seed("result-cut", 1, false, false)?;
    let mut p = open(&f.path)?;
    let loaded = load(&f, &p)?;
    let plan = PreparedReconstruction::prepare(
        &loaded,
        &p,
        bounds(),
        ReconstructionLimits::default(),
        &Clock(1000),
        &NeverCancel,
        &mut work(),
    )?;
    // Publish the exact original windows first. Existing-root retries do not hit new-root cuts.
    for (i, w) in plan.windows().iter().enumerate() {
        let mut job = fss_reference::rtsp::recording::local::RecordingPublication::new(
            w.publication_plan(),
            &mut p,
            plan.window_slot(i)?,
            w.byte_len(),
            u64::MAX,
        )?;
        let mut done = false;
        for _ in 0..5 {
            if matches!(
                job.step(1000, &NeverCancel)?,
                fss_reference::rtsp::recording::local::RecordingProgress::Published(_)
            ) {
                done = true;
                break;
            }
        }
        assert!(done);
    }
    p.inject_crash_at(PublishCutPoint::AfterRootRename);
    let error = plan
        .publish(&mut p, u64::MAX, &Clock(1000), &NeverCancel, &mut work())
        .err()
        .ok_or("lost result acknowledgement unexpectedly succeeded")?;
    assert_eq!(error.windows.len(), plan.windows().len());
    drop(p);
    let mut p = open(&f.path)?;
    let result = plan.publish(&mut p, u64::MAX, &Clock(1000), &NeverCancel, &mut work())?;
    assert_eq!(result.completion.outcome, PublishOutcome::AlreadyPublished);
    assert_eq!(result.pin, *plan.pin());
    Ok(())
}

#[test]
fn originals_are_reverified_between_complete_preparation_and_output_publication() -> Test {
    let f = seed("changed-original", 1, false, false)?;
    let mut p = open(&f.path)?;
    let loaded = load(&f, &p)?;
    let plan = PreparedReconstruction::prepare(
        &loaded,
        &p,
        bounds(),
        ReconstructionLimits::default(),
        &Clock(1000),
        &NeverCancel,
        &mut work(),
    )?;
    let identity = f.payload.to_text();
    let hex = identity
        .strip_prefix("sha256:")
        .ok_or("wrong fixture digest")?;
    std::fs::write(
        f.path.join("spool/objects").join(hex),
        b"corrupted original envelope",
    )?;
    let error = plan
        .publish(&mut p, u64::MAX, &Clock(1000), &NeverCancel, &mut work())
        .err()
        .ok_or("published from vanished originals")?;
    assert!(error.windows.is_empty());
    assert!(p.root(&plan.pin().slot).is_none());
    assert!(p.root(&plan.window_slot(0)?).is_none());
    assert_eq!(plan.windows().len(), 1);
    Ok(())
}

#[test]
fn real_eob_preserves_the_unread_selected_tail_in_the_result_identity() -> Test {
    let f = seed_eob("operator-eob")?;
    let mut p = open(&f.path)?;
    let loaded = load(&f, &p)?;
    let plan = PreparedReconstruction::prepare(
        &loaded,
        &p,
        bounds(),
        ReconstructionLimits::default(),
        &Clock(1000),
        &NeverCancel,
        &mut work(),
    )?;
    assert!(plan.summary().end_of_bitstream);
    assert_eq!(plan.summary().remaining_datagrams, 1);
    assert_eq!(
        plan.summary().observations_read + 1,
        loaded.pin().source.datagrams
    );
    assert_eq!(plan.summary().rtcp_observations, 0);
    assert_eq!(plan.summary().windows, 1);
    assert_eq!(plan.retained().boundary, Some(fss_reference::rtsp::datagram_reconstruction::hevc::recording::HevcReplayBoundary::EndOfBitstream));
    plan.publish(&mut p, u64::MAX, &Clock(1000), &NeverCancel, &mut work())?;
    Ok(())
}
#[test]
fn current_descendants_are_verified_but_do_not_change_the_historical_recipe() -> Test {
    let f = seed("operator-historical", 1, false, false)?;
    let mut p = open(&f.path)?;
    let candidate = {
        let loaded = load(&f, &p)?;
        PreparedReconstruction::prepare(
            &loaded,
            &p,
            bounds(),
            ReconstructionLimits::default(),
            &Clock(1000),
            &NeverCancel,
            &mut work(),
        )?
        .pin()
        .clone()
    };
    let mut archive = fss_reference::rtsp::datagram_archive::DatagramArchive::recover(
        &p,
        source_scope()?,
        source::limits(),
        None,
        &NeverCancel,
        &mut work(),
    )?;
    source::append(&mut p, &mut archive, &[(1, 100, vec![0, 0, 0])])?;
    let loaded = load(&f, &p)?;
    assert_eq!(
        loaded.observed_source_head().datagrams,
        f.pin.source.datagrams + 1
    );
    let plan = PreparedReconstruction::prepare(
        &loaded,
        &p,
        bounds(),
        ReconstructionLimits::default(),
        &Clock(1000),
        &NeverCancel,
        &mut work(),
    )?;
    assert_eq!(plan.pin(), &candidate);
    assert_eq!(plan.summary().rtcp_observations, 0);
    Ok(())
}
#[test]
fn published_outputs_cold_decode_to_the_same_pixels_after_recipe_owners_drop() -> Test {
    let f = seed("operator-pixels", 2, false, false)?;
    let expected = {
        let mut p = open(&f.path)?;
        let loaded = load(&f, &p)?;
        let plan = PreparedReconstruction::prepare(
            &loaded,
            &p,
            bounds(),
            ReconstructionLimits::default(),
            &Clock(1000),
            &NeverCancel,
            &mut work(),
        )?;
        let values = plan
            .windows()
            .iter()
            .enumerate()
            .map(|(i, w)| Ok((plan.window_slot(i)?, w.manifest().root(), decode_pixels(w)?)))
            .collect::<Test<Vec<_>>>()?;
        plan.publish(&mut p, u64::MAX, &Clock(1000), &NeverCancel, &mut work())?;
        values
    };
    let p = open(&f.path)?;
    for (slot, root, expected) in expected {
        let w = load_hevc_recording(&p, &slot, root, &source::media::scope()?, &NeverCancel)?;
        assert_eq!(decode_pixels(&w)?, expected);
    }
    Ok(())
}

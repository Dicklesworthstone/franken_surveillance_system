#![forbid(unsafe_code)]
//! Native filesystem custody, root crash cuts and loss of all original recipe/timing objects.
use super::*;
use fss_object::ObjectManifest;
use fss_publication::{LocalPublicationState, PublishOutcome, SlotName};
use fss_reference::rtsp::recording::local::{
    RecordingProgress, RecordingPublication, load_recording,
};
use fss_reference::rtsp::recording_recipe::storage::*;

fn store_limits() -> RecipeStorageLimits {
    RecipeStorageLimits {
        max_source_roots: 128,
        max_spool_object_bytes: 65536,
    }
}
fn publish(
    p: &mut LocalRootPublisher,
    a: &DatagramArchive,
    recipe: &RecordingRecipe,
) -> Test<RecordingRecipePin> {
    let job =
        PreparedRecordingRecipe::prepare(recipe, a, p, store_limits(), &NeverCancel, &mut work())?;
    let pin = job.pin().clone();
    let result = job.publish(p, &NeverCancel, &mut work())?;
    assert_eq!(result.pin, pin);
    assert_eq!(result.local.claims.local, LocalPublicationState::Durable);
    Ok(pin)
}
fn load(
    p: &LocalRootPublisher,
    a: &DatagramArchive,
    pin: &RecordingRecipePin,
) -> Test<RecordingRecipe> {
    Ok(load_recording_recipe(
        p,
        pin,
        a,
        recipe_limits(),
        store_limits(),
        &NeverCancel,
        &mut work(),
    )?)
}
#[test]
fn source_closed_recipe_survives_process_state_loss_and_rebuilds_publishable_identical_media()
-> Test {
    let path = fresh("recipe_storage_cold")?;
    let source_pin = save(&path, &observations(true)?)?;
    let (pin, expected) = {
        let (mut p, a) = reopen(&path, source_pin)?;
        let (recipe, mut expected) = record_decisions(&p, &a)?;
        let pin = publish(&mut p, &a, &recipe)?;
        assert_eq!(expected.len(), 1);
        (pin, expected.remove(0))
    }; // Original parameters, decision Vec, canonical recipe bytes, publisher and archive are gone.
    let result_root = {
        let (mut p, a) = reopen(&path, source_pin)?;
        let restored = load(&p, &a, &pin)?;
        assert_eq!(restored.identity(), pin.recipe);
        let mut windows = run(&restored, &a, &p, 4_000_000_000_000)?;
        assert_eq!(windows.len(), 1);
        let window = windows.remove(0);
        assert_eq!(window.manifest(), expected.manifest());
        assert_eq!(window.objects().source, expected.objects().source);
        assert_eq!(window.objects().media, expected.objects().media);
        let root = window.manifest().root();
        let mut writer = RecordingPublication::new(
            &window,
            &mut p,
            SlotName::parse("recipe-restored-window")?,
            window.byte_len(),
            u64::MAX,
        )?;
        let mut done = false;
        for _ in 0..5 {
            if let RecordingProgress::Published(receipt) =
                writer.step(4_000_000_000_001, &NeverCancel)?
            {
                assert_eq!(receipt.root, root);
                done = true;
                break;
            }
        }
        assert!(done);
        root
    };
    let p = LocalRootPublisher::open(&path, storage())?;
    let loaded = load_recording(
        &p,
        &SlotName::parse("recipe-restored-window")?,
        result_root,
        &recording()?.scope,
        &NeverCancel,
    )?;
    assert_eq!(loaded.objects().media, expected.objects().media);
    assert_eq!(loaded.objects().index, expected.objects().index);
    Ok(())
}
#[test]
fn exact_recipe_retry_reverifies_one_root_without_duplicating_source_observations() -> Test {
    let (mut p, a, recipe, _) = fixture("recipe_storage_retry")?;
    let before = p.visible_roots().count();
    let job = PreparedRecordingRecipe::prepare(
        &recipe,
        &a,
        &p,
        store_limits(),
        &NeverCancel,
        &mut work(),
    )?;
    let first = job.publish(&mut p, &NeverCancel, &mut work())?;
    assert_eq!(first.local.outcome, PublishOutcome::Published);
    let second = job.publish(&mut p, &NeverCancel, &mut work())?;
    assert_eq!(second.local.outcome, PublishOutcome::AlreadyPublished);
    assert_eq!(first.pin, second.pin);
    assert_eq!(p.visible_roots().count(), before + 1);
    assert_eq!(a.pin().datagrams, 3);
    Ok(())
}
#[test]
fn every_root_publication_cut_preserves_candidate_and_never_reports_false_durability() -> Test {
    for (index, cut) in [
        PublishCutPoint::AfterChildrenVerified,
        PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite,
        PublishCutPoint::AfterRootRename,
    ]
    .into_iter()
    .enumerate()
    {
        let path = fresh(&format!("recipe_storage_crash_{index}"))?;
        let source_pin = save(&path, &observations(true)?)?;
        let pin = {
            let (mut p, a) = reopen(&path, source_pin)?;
            let (recipe, _) = record_decisions(&p, &a)?;
            let job = PreparedRecordingRecipe::prepare(
                &recipe,
                &a,
                &p,
                store_limits(),
                &NeverCancel,
                &mut work(),
            )?;
            let pin = job.pin().clone();
            p.inject_crash_at(cut);
            assert!(job.publish(&mut p, &NeverCancel, &mut work()).is_err());
            assert_eq!(job.pin(), &pin);
            assert!(p.is_poisoned());
            pin
        };
        let (p, a) = reopen(&path, source_pin)?;
        let result = load(&p, &a, &pin);
        if cut == PublishCutPoint::AfterRootRename {
            assert_eq!(result?.identity(), pin.recipe);
        } else {
            assert!(result.is_err());
        }
    }
    Ok(())
}
#[test]
fn corrupt_original_after_preparation_blocks_publication_and_after_commit_blocks_loading() -> Test {
    for committed in [false, true] {
        let (mut p, a, recipe, _) = fixture(if committed {
            "recipe_storage_corrupt_committed"
        } else {
            "recipe_storage_corrupt_prepared"
        })?;
        let job = PreparedRecordingRecipe::prepare(
            &recipe,
            &a,
            &p,
            store_limits(),
            &NeverCancel,
            &mut work(),
        )?;
        let pin = job.pin().clone();
        if committed {
            let _ = job.publish(&mut p, &NeverCancel, &mut work())?;
        }
        let hex: String = a.records()[0]
            .payload_digest
            .bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        std::fs::write(
            p.root_dir().join("spool/objects").join(hex),
            b"corrupt original envelope",
        )?;
        if committed {
            assert!(load(&p, &a, &pin).is_err());
        } else {
            assert!(job.publish(&mut p, &NeverCancel, &mut work()).is_err());
            assert!(p.root(&pin.slot).is_none());
        }
    }
    Ok(())
}
#[test]
fn incomplete_or_extra_source_graph_cannot_impersonate_recipe_publication() -> Test {
    for extra in [false, true] {
        let (mut p, a, recipe, _) = fixture(if extra {
            "recipe_storage_extra"
        } else {
            "recipe_storage_missing"
        })?;
        let original = PreparedRecordingRecipe::prepare(
            &recipe,
            &a,
            &p,
            store_limits(),
            &NeverCancel,
            &mut work(),
        )?;
        let mut pin = original.pin().clone();
        drop(original);
        let metadata = p.stage_object(recipe.canonical_bytes())?;
        let mut children: Vec<_> = a.records().iter().map(|r| r.pin.head).collect();
        if extra {
            children.push(p.stage_object(b"unaccounted source")?);
        } else {
            let _ = children.pop();
        }
        let forged = ObjectManifest::new(RECORDING_RECIPE_KIND, children, Some(metadata))?;
        let _ = p.publish_cancellable(&pin.slot, &forged, &NeverCancel)?;
        pin.root = forged.root();
        assert!(load(&p, &a, &pin).is_err());
    }
    Ok(())
}
#[test]
fn resource_and_cancellation_refusals_have_no_new_root_side_effects() -> Test {
    let (mut p, a, recipe, _) = fixture("recipe_storage_bounds")?;
    let before = p.visible_roots().count();
    for ceiling in [
        RecipeStorageLimits {
            max_source_roots: 2,
            ..store_limits()
        },
        RecipeStorageLimits {
            max_spool_object_bytes: 1024,
            ..store_limits()
        },
    ] {
        assert!(
            PreparedRecordingRecipe::prepare(&recipe, &a, &p, ceiling, &NeverCancel, &mut work())
                .is_err()
        );
    }
    let job = PreparedRecordingRecipe::prepare(
        &recipe,
        &a,
        &p,
        store_limits(),
        &NeverCancel,
        &mut work(),
    )?;
    assert!(job.publish(&mut p, &Stop, &mut work()).is_err());
    assert!(
        job.publish(&mut p, &NeverCancel, &mut fss_geometry::WorkBudget::new(0))
            .is_err()
    );
    assert_eq!(p.visible_roots().count(), before);
    Ok(())
}
#[test]
fn independently_selected_pin_and_source_cannot_be_replaced_on_load() -> Test {
    let (mut p, a, recipe, _) = fixture("recipe_storage_pin")?;
    let pin = publish(&mut p, &a, &recipe)?;
    let mut wrong = pin.clone();
    wrong.recipe = ContentDigest::sha256(b"other recipe");
    assert!(load(&p, &a, &wrong).is_err());
    let mut wrong = pin.clone();
    wrong.source.payload_bytes += 1;
    assert!(load(&p, &a, &wrong).is_err());
    let mut wrong = pin;
    wrong.root = ContentDigest::sha256(b"other graph");
    assert!(load(&p, &a, &wrong).is_err());
    Ok(())
}
#[test]
fn retained_recipe_is_not_a_claim_that_its_incorrect_timing_program_executed() -> Test {
    let (mut p, a, recipe, _) = fixture("recipe_storage_unproved")?;
    let mut decisions = recipe.timings().to_vec();
    decisions[0].picture.rtp_timestamp += 1;
    let wrong = RecordingRecipe::new(&a, spec()?, recording()?, decisions, recipe_limits())?;
    let pin = publish(&mut p, &a, &wrong)?;
    let loaded = load(&p, &a, &pin)?;
    assert!(run(&loaded, &a, &p, 1000).is_err());
    assert_eq!(p.visible_roots().count(), a.records().len() + 1);
    Ok(())
}
#[test]
fn disappearing_source_after_recipe_commit_is_not_replaced_from_stale_metadata() -> Test {
    let (mut p, a, recipe, _) = fixture("recipe_storage_vanished")?;
    let pin = publish(&mut p, &a, &recipe)?;
    let hex: String = a.records()[0]
        .payload_digest
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    std::fs::remove_file(p.root_dir().join("spool/objects").join(hex))?;
    assert!(load(&p, &a, &pin).is_err());
    Ok(())
}
#[test]
fn cancellation_after_timing_admission_preserves_the_withheld_native_result() -> Test {
    use std::cell::Cell;
    struct Cut {
        calls: Cell<usize>,
        at: usize,
    }
    impl PublishCancellation for Cut {
        fn cancel_requested(&self, _: PublishCutPoint) -> bool {
            let n = self.calls.get() + 1;
            self.calls.set(n);
            n == self.at
        }
    }
    let (p, a, recipe, _) = fixture("recipe_post_timing_cancel")?;
    let mut saw_withheld = false;
    for at in 1..=8 {
        let mut replay = PlannedRecordingReplay::new(&recipe, &a, recipe_limits(), bounds(), 1000)?;
        let mut ready = false;
        for _ in 0..128 {
            if let RecipeReplayStep::Replay(RecordingReplayStep::Capture(event)) =
                replay.step(&p, 1000, &NeverCancel, &mut work())?
                && matches!(*event, CapturePoll::TimingRequired(_))
            {
                ready = true;
                break;
            }
        }
        assert!(ready);
        if let Err(failure) = replay.step(
            &p,
            1000,
            &Cut {
                calls: Cell::new(0),
                at,
            },
            &mut work(),
        ) {
            assert_eq!(replay.timings_applied(), 0);
            let retired = failure
                .retirement
                .ok_or("fatal cancellation lacks ownership")?;
            saw_withheld |= retired
                .recording
                .as_ref()
                .is_some_and(|r| r.withheld_timing.is_some());
        }
    }
    assert!(
        saw_withheld,
        "no exercised cancellation retained the admitted timing outcome"
    );
    Ok(())
}

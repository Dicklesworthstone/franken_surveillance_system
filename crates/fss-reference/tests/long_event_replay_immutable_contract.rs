#![forbid(unsafe_code)]
//! Native long-event metadata inspection under one immutable owner and a live writer.
//! Synthetic publications exercise custody, cancellation and admission, not detection accuracy.

#[path = "long_event_replay_immutable_contract/fixtures.rs"]
mod fixtures;
#[path = "long_event_replay_immutable_contract/native.rs"]
mod native;
#[path = "cascade_support/mod.rs"]
mod support;

use std::fs;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_core::{CanonicalEncode, ContentDigest, SensorId};
use fss_publication::root_record_bytes;
use fss_reference::ingest::FileIngestError;
use fss_reference::ingest::long_event_replay::{
    LongEventReplayError, LongEventReplayInspection, LongEventReplayLimits, LongEventReplayRecipe,
    inspect_long_event,
};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::retained_source::{ImmutableRetainedSource, RetainedSource};
use fss_reference::{ReferencePolicyAction, ReferencePolicyDecision, ReplayCx};

use fixtures::{Profile, Published, SENSOR, context, limits, tree};
use support::TestResult as Test;

fn inspect(
    source: &ImmutableRetainedSource<'_>,
    fixture: &Published,
    cx: &ReplayCx,
) -> Test<LongEventReplayInspection> {
    Ok(inspect_long_event(
        source,
        &fixture.event.event_id,
        &LongEventReplayLimits::default(),
        cx,
    )?)
}

fn finish(source: &ImmutableRetainedSource<'_>) -> Result<(), FileIngestError> {
    source.revalidate_snapshot_metadata()?;
    source.revalidate()
}

#[test]
fn watch_and_dwell_metadata_remain_readable_with_a_live_writer_and_missing_source_pixels() -> Test {
    for profile in [Profile::Watch, Profile::Dwell] {
        let fixture = Published::new(&format!("long-immutable-live-{profile:?}"), profile)?;
        for chunk in &fixture.source_chunks {
            fs::remove_file(fixture.object_path(*chunk))?;
        }
        fs::write(
            fixture.root().join("LAYOUT.tmp.immutable-must-preserve"),
            b"unrelated recovery state must remain untouched",
        )?;
        let before = tree(fixture.root())?;
        let cx = context(fixture.root())?;
        cx.set_cancel_at_checkpoint("long_event_replay:execute");
        let source = ImmutableRetainedSource::open(fixture.root(), limits(), &cx)?;
        let result = inspect(&source, &fixture, &cx)?;
        assert_eq!(result.event(), &fixture.event);
        assert_eq!(result.pins(), fixture.pins());
        assert_eq!(result.event_root(), fixture.event_root);
        assert_eq!(result.analysis_digests(), &[fixture.analysis_digest]);
        assert_eq!(result.analysis_roots(), &[fixture.analysis_root]);
        match result.recipe() {
            LongEventReplayRecipe::Watch(recipe) => {
                assert!(matches!(profile, Profile::Watch));
                assert_eq!(recipe.plan(), &fixture.plan);
            }
            LongEventReplayRecipe::Dwell(recipe) => {
                assert!(matches!(profile, Profile::Dwell));
                assert_eq!(recipe.plan(), &fixture.plan);
                assert_eq!(recipe.rule().minimum_observations, 3);
            }
            LongEventReplayRecipe::Corroboration(_) => return Err("unexpected profile".into()),
        }
        let selected = source.usage();
        finish(&source)?;
        assert!(source.usage().read_bytes > selected.read_bytes);
        assert!(source.usage().read_objects > selected.read_objects);
        assert_eq!(result.basis(), fixture.storage.deployment.current_anchor());
        assert!(
            !cx.is_cancelled(),
            "metadata inspection entered native perception"
        );
        assert_eq!(tree(fixture.root())?, before);
        drop(source);
        cx.drain_and_finalize();
    }
    Ok(())
}

#[test]
fn final_metadata_custody_and_head_checks_share_the_exact_original_allowance() -> Test {
    let fixture = Published::new("long-immutable-budget", Profile::Dwell)?;
    let before = tree(fixture.root())?;
    let cx = context(fixture.root())?;
    let complete = ImmutableRetainedSource::open(fixture.root(), limits(), &cx)?;
    inspect(&complete, &fixture, &cx)?;
    let selected = complete.usage();
    finish(&complete)?;
    let total = complete.usage();
    assert!(total.read_bytes > selected.read_bytes + 1);
    assert!(total.read_objects > selected.read_objects + 1);
    drop(complete);

    let mut exact = limits();
    exact.max_read_bytes = usize::try_from(total.read_bytes)?;
    exact.max_read_objects = usize::try_from(total.read_objects)?;
    let admitted = ImmutableRetainedSource::open(fixture.root(), exact, &cx)?;
    assert_eq!(inspect(&admitted, &fixture, &cx)?.pins(), fixture.pins());
    finish(&admitted)?;
    assert_eq!(admitted.usage(), total);
    drop(admitted);

    for bytes in [true, false] {
        let mut short = exact;
        if bytes {
            short.max_read_bytes -= 1;
        } else {
            short.max_read_objects -= 1;
        }
        let source = ImmutableRetainedSource::open(fixture.root(), short, &cx)?;
        assert_eq!(inspect(&source, &fixture, &cx)?.pins(), fixture.pins());
        assert_eq!(source.usage(), selected);
        assert!(
            finish(&source).is_err(),
            "final verification renewed the allowance"
        );
        assert!(source.read_object(fixture.analysis_digest).is_err());
        assert!(
            source.revalidate().is_err(),
            "failed allowance was reusable"
        );
    }
    assert_eq!(tree(fixture.root())?, before);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn cancellation_at_the_last_live_admission_refuses_finalization_and_poisons_the_owner() -> Test {
    let fixture = Published::new("long-immutable-final-cancel", Profile::Watch)?;
    let before = tree(fixture.root())?;
    let cx = context(fixture.root())?;
    let calls = AtomicUsize::new(0);
    let count = || {
        calls.fetch_add(1, Ordering::SeqCst);
        false
    };
    let calibration =
        ImmutableRetainedSource::open_cancellable(fixture.root(), limits(), &cx, &count)?;
    inspect(&calibration, &fixture, &cx)?;
    let selected_calls = calls.load(Ordering::SeqCst);
    finish(&calibration)?;
    let last = calls.load(Ordering::SeqCst);
    assert!(last > selected_calls);
    drop(calibration);

    calls.store(0, Ordering::SeqCst);
    let fired = AtomicBool::new(false);
    let cancel_last = || {
        if calls.fetch_add(1, Ordering::SeqCst) + 1 == last {
            fired.store(true, Ordering::SeqCst);
        }
        fired.load(Ordering::SeqCst)
    };
    let source =
        ImmutableRetainedSource::open_cancellable(fixture.root(), limits(), &cx, &cancel_last)?;
    inspect(&source, &fixture, &cx)?;
    assert!(matches!(
        finish(&source),
        Err(FileIngestError::CancellationRequested { .. })
    ));
    assert!(fired.load(Ordering::SeqCst));
    // Even after the external probe clears, the refused owner cannot renew its allowance.
    fired.store(false, Ordering::SeqCst);
    assert!(source.read_object(fixture.analysis_digest).is_err());
    assert!(source.revalidate().is_err());
    assert_eq!(tree(fixture.root())?, before);
    drop(source);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn selected_payload_changes_after_inspection_refuse_without_repair() -> Test {
    let fixture = Published::new("long-immutable-final-payload", Profile::Watch)?;
    let cx = context(fixture.root())?;
    let event_payload = ContentDigest::sha256(&fixture.event.try_canonical_bytes()?);
    for digest in [
        fixture.event_root,
        event_payload,
        fixture.pins().provenance_root,
        fixture.analysis_root,
        fixture.analysis_digest,
        fixture.quiet_capsule,
    ] {
        let source = ImmutableRetainedSource::open(fixture.root(), limits(), &cx)?;
        inspect(&source, &fixture, &cx)?;
        let path = fixture.object_path(digest);
        let original = fs::read(&path)?;
        let mut damaged = original.clone();
        *damaged.last_mut().ok_or("empty retained object")? ^= 1;
        fs::write(&path, &damaged)?;
        let before = tree(fixture.root())?;
        assert!(
            finish(&source).is_err(),
            "changed retained payload {digest}"
        );
        assert_eq!(tree(fixture.root())?, before, "refusal repaired {digest}");
        drop(source);
        fs::write(path, original)?;
    }
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn validly_encoded_candidate_and_analysis_publication_count_changes_refuse_finalization() -> Test {
    let fixture = Published::new("long-immutable-final-publication", Profile::Dwell)?;
    let cx = context(fixture.root())?;
    for root in [fixture.pins().provenance_root, fixture.analysis_root] {
        let source = ImmutableRetainedSource::open(fixture.root(), limits(), &cx)?;
        inspect(&source, &fixture, &cx)?;
        let (path, slot, children) = fixture.publication(root)?;
        let original = fs::read(&path)?;
        let changed = root_record_bytes(&slot, root, children + 1)?;
        assert_ne!(changed, original);
        fs::write(&path, changed)?;
        let before = tree(fixture.root())?;
        assert!(
            finish(&source).is_err(),
            "publication child count was ignored"
        );
        assert_eq!(tree(fixture.root())?, before);
        drop(source);
        fs::write(path, original)?;
    }
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn new_event_revision_and_privacy_authority_each_invalidate_a_completed_inspection() -> Test {
    for privacy in [false, true] {
        let mut fixture =
            Published::new(&format!("long-immutable-head-{privacy}"), Profile::Watch)?;
        let root = fixture.root().to_path_buf();
        let cx = context(&root)?;
        let source = ImmutableRetainedSource::open(&root, limits(), &cx)?;
        inspect(&source, &fixture, &cx)?;
        if privacy {
            let mask =
                PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [48, 32], &[[40, 0, 8, 32]])?;
            let approval = preview_mask(&fixture.storage.deployment, &mask)?.approval;
            declare_mask(
                &mut fixture.storage.deployment,
                &mask,
                approval,
                &fixture.storage.cx,
            )?;
        } else {
            let mut successor = fixture.event.clone();
            successor.supersedes = Some(successor.revision_digest());
            successor.revision = 2;
            successor.uncertainty_reason = Some("subsequent review".into());
            fixture.storage.deployment.publish_event(
                &ReferencePolicyDecision {
                    event: successor,
                    action: ReferencePolicyAction::Hold,
                },
                &fixture.storage.cx,
            )?;
        }
        let changed = tree(&root)?;
        assert!(
            finish(&source).is_err(),
            "stale current authority was accepted"
        );
        assert_eq!(tree(&root)?, changed);
        drop(source);

        let fresh = ImmutableRetainedSource::open(&root, limits(), &cx)?;
        let result = inspect_long_event(
            &fresh,
            &fixture.event.event_id,
            &LongEventReplayLimits::default(),
            &cx,
        );
        if privacy {
            assert!(matches!(result, Err(LongEventReplayError::PrivacyChanged)));
        } else {
            assert!(matches!(
                result,
                Err(LongEventReplayError::UnsupportedProfile)
            ));
        }
        assert_eq!(tree(&root)?, changed);
        drop(fresh);
        cx.drain_and_finalize();
    }
    Ok(())
}

#[test]
fn incomplete_ledger_and_effect_tails_are_refused_without_truncation_or_recovery() -> Test {
    let fixture = Published::new("long-immutable-damaged-journals", Profile::Watch)?;
    let cx = context(fixture.root())?;
    for journal in ["ledger/journal.fssj", "effects/journal.fssj"] {
        let path = fixture.root().join(journal);
        let original = fs::read(&path)?;
        let mut damaged = original.clone();
        damaged.extend_from_slice(b"\x01\x02\x03");
        fs::write(&path, &damaged)?;
        let before = tree(fixture.root())?;
        assert!(
            ImmutableRetainedSource::open(fixture.root(), limits(), &cx).is_err(),
            "{journal}"
        );
        assert_eq!(
            tree(fixture.root())?,
            before,
            "inspection repaired {journal}"
        );
        fs::write(path, original)?;
    }
    cx.drain_and_finalize();
    Ok(())
}

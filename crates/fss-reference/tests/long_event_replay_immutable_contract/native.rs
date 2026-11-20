#![forbid(unsafe_code)]
//! Actual retained-media replay shares one immutable allowance through delivery validation.

use super::*;
use fss_reference::ingest::long_event_replay::{VerifiedLongEventReplay, replay_long_event};

fn replay(
    source: &ImmutableRetainedSource<'_>,
    fixture: &Published,
    cx: &ReplayCx,
) -> Test<VerifiedLongEventReplay> {
    Ok(replay_long_event(
        source,
        &fixture.event.event_id,
        fixture.pins(),
        &LongEventReplayLimits::default(),
        cx,
    )?)
}

#[test]
fn native_watch_and_dwell_replay_with_the_writer_open_without_mutating_custody() -> Test {
    for profile in [Profile::Watch, Profile::Dwell] {
        let fixture = Published::new(&format!("long-immutable-native-{profile:?}"), profile)?;
        let before = tree(fixture.root())?;
        let cx = context(fixture.root())?;
        let source = ImmutableRetainedSource::open(fixture.root(), limits(), &cx)?;
        let verified = replay(&source, &fixture, &cx)?;
        assert_eq!(verified.inspection().event(), &fixture.event);
        assert_eq!(verified.inspection().pins(), fixture.pins());
        assert_eq!(verified.frames_replayed(), fixture.plan.segment_count);
        assert!(verified.source_chunk_bytes_read() > 0);
        finish(&source)?;
        assert_eq!(tree(fixture.root())?, before);
        drop(source);
        cx.drain_and_finalize();
    }
    Ok(())
}

#[test]
fn native_replay_and_final_rereads_share_exact_nonrenewing_byte_and_object_budgets() -> Test {
    let fixture = Published::new("long-immutable-native-budget", Profile::Watch)?;
    let before = tree(fixture.root())?;
    let cx = context(fixture.root())?;
    let source = ImmutableRetainedSource::open(fixture.root(), limits(), &cx)?;
    replay(&source, &fixture, &cx)?;
    let executed = source.usage();
    finish(&source)?;
    let total = source.usage();
    assert!(total.read_bytes > executed.read_bytes + 1);
    assert!(total.read_objects > executed.read_objects + 1);
    drop(source);
    let mut exact = limits();
    exact.max_read_bytes = usize::try_from(total.read_bytes)?;
    exact.max_read_objects = usize::try_from(total.read_objects)?;
    let source = ImmutableRetainedSource::open(fixture.root(), exact, &cx)?;
    replay(&source, &fixture, &cx)?;
    finish(&source)?;
    assert_eq!(source.usage(), total);
    drop(source);
    for bytes in [true, false] {
        let mut short = exact;
        if bytes {
            short.max_read_bytes -= 1;
        } else {
            short.max_read_objects -= 1;
        }
        let source = ImmutableRetainedSource::open(fixture.root(), short, &cx)?;
        replay(&source, &fixture, &cx)?;
        assert_eq!(source.usage(), executed);
        assert!(finish(&source).is_err());
        assert!(source.read_object(fixture.analysis_digest).is_err());
    }
    assert_eq!(tree(fixture.root())?, before);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn native_replay_refuses_cancellation_at_execution_and_at_the_last_delivery_read() -> Test {
    let fixture = Published::new("long-immutable-native-cancel", Profile::Dwell)?;
    let before = tree(fixture.root())?;
    let cx = context(fixture.root())?;
    cx.set_cancel_at_checkpoint("long_event_replay:execute");
    let source = ImmutableRetainedSource::open(fixture.root(), limits(), &cx)?;
    assert!(replay(&source, &fixture, &cx).is_err());
    assert!(cx.is_cancelled());
    drop(source);
    cx.drain_and_finalize();

    let cx = context(fixture.root())?;
    let calls = AtomicUsize::new(0);
    let count = || {
        calls.fetch_add(1, Ordering::SeqCst);
        false
    };
    let source = ImmutableRetainedSource::open_cancellable(fixture.root(), limits(), &cx, &count)?;
    replay(&source, &fixture, &cx)?;
    let executed = calls.load(Ordering::SeqCst);
    finish(&source)?;
    let last = calls.load(Ordering::SeqCst);
    assert!(last > executed);
    drop(source);
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
    replay(&source, &fixture, &cx)?;
    assert!(matches!(
        finish(&source),
        Err(FileIngestError::CancellationRequested { .. })
    ));
    fired.store(false, Ordering::SeqCst);
    assert!(
        source.revalidate().is_err(),
        "cancelled owner renewed its allowance"
    );
    assert_eq!(tree(fixture.root())?, before);
    drop(source);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn completed_native_replay_cannot_hide_late_source_capsule_or_event_damage() -> Test {
    let fixture = Published::new("long-immutable-native-damage", Profile::Watch)?;
    let cx = context(fixture.root())?;
    for digest in [
        fixture.source_chunks[0],
        fixture.quiet_capsule,
        fixture.event_root,
    ] {
        let source = ImmutableRetainedSource::open(fixture.root(), limits(), &cx)?;
        replay(&source, &fixture, &cx)?;
        let path = fixture.object_path(digest);
        let original = fs::read(&path)?;
        let mut damaged = original.clone();
        *damaged.last_mut().ok_or("empty retained object")? ^= 1;
        fs::write(&path, &damaged)?;
        let before = tree(fixture.root())?;
        assert!(
            finish(&source).is_err(),
            "late damage escaped final verification: {digest}"
        );
        assert_eq!(tree(fixture.root())?, before);
        drop(source);
        fs::write(path, original)?;
    }
    cx.drain_and_finalize();
    Ok(())
}

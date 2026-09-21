#![forbid(unsafe_code)]
//! Actual source-linked recordings and filesystem custody, not a substitute journal.
mod recording_support;
use recording_support::{fixture, scope, Error};
use fss_container::TimedAvcPicture;
use fss_core::ContentDigest;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel,
    PublishCancellation, PublishCutPoint};
use fss_reference::rtsp::archive_recovery::{archive_retirement_digest, ArchiveResumeConfig,
    ArchiveResumeProgress, RecordingArchiveResume, RetiredPublicationState};
use fss_reference::rtsp::recording::{prepare_recording, PreparedRecording, RecordingPacket};
use fss_reference::rtsp::recording_archive::{ArchiveError, ArchiveLimits, ArchiveNamespace,
    ArchiveWriteProgress, RecordingArchiveWriter};
use fss_reference::rtsp::recording_archive::checkpoint::{ArchiveWorkLimits, PreparedArchiveWork, load_archive_work};
use fss_reference::rtsp::recording_archive::checkpoint::write_ahead::*;
use fss_reference::rtsp::recording_catalog::CatalogScope;
use std::path::{Path, PathBuf};

type Test<T = ()> = Result<T, Error>;
fn fresh(name: &str) -> Test<PathBuf> {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("archive_write_ahead").join(name);
    match std::fs::remove_dir_all(&path) {
        Ok(()) => {}, Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}, Err(e) => return Err(e.into()),
    }
    Ok(path)
}
fn storage_limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(128, 1024, 128, 1024,
        SpoolLimits::new(1024, 16 * 1024 * 1024, 1024 * 1024, 1024))
}
fn limits() -> ArchiveLimits {
    ArchiveLimits { max_windows: 8, max_pages: 8, max_scan_roots: 256, windows_per_page: 2 }
}
fn namespace() -> Test<ArchiveNamespace> {
    Ok(ArchiveNamespace::new(CatalogScope { recording: scope()?,
        decode_clock: ContentDigest::sha256(b"write-ahead test clock"), time_scale: 90_000 })?)
}
fn window(at: u64) -> Test<PreparedRecording> {
    let f = fixture(31, true)?;
    let pictures: Vec<_> = f.pictures.iter().enumerate().map(|(i, picture)| TimedAvcPicture {
        picture, decode_time: at + i as u64 * 3600, duration: 3600, composition_offset: 0,
    }).collect();
    let packets: Vec<_> = f.packets.iter().map(|(sequence, received_ns, bytes)| RecordingPacket {
        sequence: *sequence, received_ns: *received_ns, bytes,
    }).collect();
    Ok(prepare_recording(scope()?, 90_000, &pictures, &packets)?)
}
fn open(p: &mut LocalRootPublisher) -> Test<CheckpointedArchiveWriter<'_>> {
    Ok(CheckpointedArchiveWriter::open(p, namespace()?, limits(), ArchiveWorkLimits::default(),
        1000, 0, 1000, &NeverCancel)?)
}
fn offer(w: &mut CheckpointedArchiveWriter<'_>, at: u64) -> Test<ContentDigest> {
    let window = window(at)?; let root = window.manifest().root(); let bytes = window.byte_len();
    w.offer(window, bytes, 2)?; Ok(root)
}
fn pin(w: &mut CheckpointedArchiveWriter<'_>) -> Test<ArchiveCheckpoint> {
    match w.step(2, &NeverCancel)? {
        CheckpointedArchiveProgress::PinRequired(pin) => Ok(pin),
        other => Err(format!("expected read-only pin, got {other:?}").into()),
    }
}
fn protect(w: &mut CheckpointedArchiveWriter<'_>) -> Test<ArchiveCheckpoint> {
    let pin = pin(w)?; w.acknowledge_checkpoint(&pin, 2, &NeverCancel)?;
    match w.step(2, &NeverCancel)? {
        CheckpointedArchiveProgress::WorkDurable { checkpoint, receipt } => {
            assert_eq!(checkpoint, pin); assert_eq!(receipt.root, pin.root()); Ok(pin)
        }
        _ => Err("missing whole work-root receipt".into()),
    }
}
fn drain(w: &mut CheckpointedArchiveWriter<'_>) -> Test<Vec<ArchiveCheckpoint>> {
    let mut checkpoints = Vec::new();
    for _ in 0..100 {
        match w.step(2, &NeverCancel)? {
            CheckpointedArchiveProgress::PinRequired(pin) => w.acknowledge_checkpoint(&pin, 2, &NeverCancel)?,
            CheckpointedArchiveProgress::WorkDurable { checkpoint, receipt } => {
                assert_eq!(checkpoint.root(), receipt.root); checkpoints.push(checkpoint);
            }
            CheckpointedArchiveProgress::Archive(ArchiveWriteProgress::Ready { .. }
                | ArchiveWriteProgress::Finished { .. }) => return Ok(checkpoints),
            CheckpointedArchiveProgress::Archive(ArchiveWriteProgress::Exhausted) => return Err("unexpected exhaustion".into()),
            _ => {},
        }
    }
    Err("bounded archive did not yield".into())
}
fn prepare_page(w: &mut CheckpointedArchiveWriter<'_>) -> Test {
    assert!(matches!(w.step(2, &NeverCancel)?, CheckpointedArchiveProgress::Archive(ArchiveWriteProgress::PageStarted { .. })));
    assert!(matches!(w.step(2, &NeverCancel)?, CheckpointedArchiveProgress::Archive(ArchiveWriteProgress::PageWindowVerified { .. })));
    assert!(matches!(w.step(2, &NeverCancel)?, CheckpointedArchiveProgress::Archive(ArchiveWriteProgress::CatalogPrepared { .. })));
    Ok(())
}
struct Cancel;
impl PublishCancellation for Cancel {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool { true }
}

#[test]
fn unacknowledged_pin_cannot_publish_or_release_original_source() -> Test {
    let mut p = LocalRootPublisher::open(fresh("pin_wait")?, storage_limits())?;
    let mut w = open(&mut p)?; let root = offer(&mut w, 0)?;
    let pin = pin(&mut w)?;
    for _ in 0..5 {
        assert!(matches!(w.step(2, &NeverCancel)?, CheckpointedArchiveProgress::PinRequired(p) if p == pin));
        assert!(w.snapshot().windows().is_empty());
        assert_eq!(w.pending().ok_or("lost source")?.manifest().root(), root);
    }
    let work = w.retire(); assert_eq!(work.pending_checkpoint, Some(pin));
    assert!(work.last_durable_checkpoint.is_none());
    assert_eq!(p.visible_roots().count(), 0);
    Ok(())
}

#[test]
fn automatic_checkpoint_is_byte_identical_to_the_existing_retired_work_format() -> Test {
    let mut p = LocalRootPublisher::open(fresh("compatibility")?, storage_limits())?;
    let mut w = open(&mut p)?; offer(&mut w, 0)?;
    let pin = pin(&mut w)?;
    let work = w.retire();
    let prepared = PreparedArchiveWork::prepare(&work.archive, &p, ArchiveWorkLimits::default(), &NeverCancel)?;
    assert_eq!(pin.retirement_digest(), archive_retirement_digest(&work.archive)?);
    assert_eq!(pin.root(), prepared.root()); assert_eq!(pin.slot(), prepared.slot());
    assert_eq!(pin.new_payload_bytes(), prepared.new_payload_bytes());
    Ok(())
}

#[test]
fn cold_restart_after_checkpoint_loses_no_pending_media_before_normal_publication() -> Test {
    let path = fresh("cold")?;
    let (pin, root, children) = {
        let mut p = LocalRootPublisher::open(&path, storage_limits())?;
        let mut w = open(&mut p)?; let root = offer(&mut w, 0)?;
        let children = w.pending().ok_or("pending missing")?.children().map(|(_, d, _)| d);
        let pin = protect(&mut w)?;
        assert!(w.snapshot().windows().is_empty());
        (pin, root, children)
    }; // Lose ALL original Rust owner/media objects, not just the writer handle.
    let mut p = LocalRootPublisher::open(&path, storage_limits())?;
    assert!(p.root(&namespace()?.window_slot(0)?).is_none());
    let work = load_archive_work(&p, pin.slot(), pin.root(), ArchiveWorkLimits::default(), &NeverCancel)?;
    assert_eq!(archive_retirement_digest(&work)?, pin.retirement_digest());
    let window = work.pending.as_ref().ok_or("checkpoint lost original")?;
    assert_eq!(window.manifest().root(), root);
    assert_eq!(window.children().map(|(_, d, _)| d), children);
    let mut resume = RecordingArchiveResume::open(&mut p, work, ArchiveResumeConfig {
        expected_retirement_digest: pin.retirement_digest(), max_window_bytes: 1024 * 1024,
        max_steps: 100, deadline_ns: 1000,
    }, 3, &NeverCancel)?;
    assert_eq!(resume.reconciliation().window, RetiredPublicationState::NotPublished(root));
    for _ in 0..100 {
        if let ArchiveResumeProgress::Archive(ArchiveWriteProgress::Finished { windows, .. }) = resume.step(3, &NeverCancel)? {
            assert_eq!(windows, 1); return Ok(());
        }
    }
    Err("cold resume did not finish".into())
}

#[test]
fn lost_normal_window_ack_reconciles_without_a_second_ordinal() -> Test {
    let path = fresh("lost_window_ack")?;
    let (pin, root) = {
        let mut p = LocalRootPublisher::open(&path, storage_limits())?;
        let mut w = open(&mut p)?; let root = offer(&mut w, 0)?; let pin = protect(&mut w)?;
        // Ignore the normal WindowDurable receipt, as when the receiving process is lost.
        assert!(matches!(w.step(2, &NeverCancel)?, CheckpointedArchiveProgress::Archive(ArchiveWriteProgress::WindowDurable { .. })));
        (pin, root)
    };
    let mut p = LocalRootPublisher::open(&path, storage_limits())?;
    let work = load_archive_work(&p, pin.slot(), pin.root(), ArchiveWorkLimits::default(), &NeverCancel)?;
    let resume = RecordingArchiveResume::open(&mut p, work, ArchiveResumeConfig {
        expected_retirement_digest: pin.retirement_digest(), max_window_bytes: 1024 * 1024,
        max_steps: 100, deadline_ns: 1000,
    }, 3, &NeverCancel)?;
    assert_eq!(resume.reconciliation().window, RetiredPublicationState::AlreadyDurable(root));
    assert_eq!(resume.snapshot().windows().len(), 1); Ok(())
}

#[test]
fn automatic_catalog_barrier_precedes_index_io_and_survives_lost_page_ack() -> Test {
    let path = fresh("page_barrier")?;
    let page_pin = {
        let mut p = LocalRootPublisher::open(&path, storage_limits())?;
        let mut w = open(&mut p)?; offer(&mut w, 0)?; protect(&mut w)?;
        assert!(matches!(w.step(2, &NeverCancel)?, CheckpointedArchiveProgress::Archive(ArchiveWriteProgress::WindowDurable { .. })));
        w.finish(2)?;
        prepare_page(&mut w)?; // start page, verify window, prepare page
        assert_eq!(w.snapshot().indexed_windows(), 0);
        let pin = protect(&mut w)?;
        assert_eq!(w.snapshot().indexed_windows(), 0);
        assert!(matches!(w.step(2, &NeverCancel)?, CheckpointedArchiveProgress::Archive(ArchiveWriteProgress::CatalogIndexStaged { .. })));
        assert!(matches!(w.step(2, &NeverCancel)?, CheckpointedArchiveProgress::Archive(ArchiveWriteProgress::CatalogPublished { .. })));
        pin
    };
    let mut p = LocalRootPublisher::open(&path, storage_limits())?;
    let work = load_archive_work(&p, page_pin.slot(), page_pin.root(), ArchiveWorkLimits::default(), &NeverCancel)?;
    assert!(work.pending.is_none()); assert!(work.prepared_page.is_some());
    assert_eq!(archive_retirement_digest(&work)?, page_pin.retirement_digest());
    let resume = RecordingArchiveResume::open(&mut p, work, ArchiveResumeConfig {
        expected_retirement_digest: page_pin.retirement_digest(), max_window_bytes: 0,
        max_steps: 100, deadline_ns: 1000,
    }, 3, &NeverCancel)?;
    assert!(matches!(resume.reconciliation().page, RetiredPublicationState::AlreadyDurable(_)));
    assert_eq!(resume.snapshot().indexed_windows(), 1); Ok(())
}

#[test]
fn recovered_unindexed_tail_is_protected_before_new_page_publication() -> Test {
    let path = fresh("old_tail")?;
    {
        let mut p = LocalRootPublisher::open(&path, storage_limits())?;
        let mut w = RecordingArchiveWriter::open(&mut p, namespace()?, limits(), 0, 1000, &NeverCancel)?;
        let window = window(0)?; let bytes = window.byte_len(); w.offer(window, bytes, 0)?;
        assert!(matches!(w.step(1, &NeverCancel)?, ArchiveWriteProgress::WindowDurable { .. }));
    }
    let mut p = LocalRootPublisher::open(&path, storage_limits())?;
    let mut w = open(&mut p)?; assert_eq!(w.snapshot().unindexed_windows().len(), 1);
    let pins = drain(&mut w)?; assert_eq!(pins.len(), 1);
    assert_eq!(w.snapshot().indexed_windows(), 1); Ok(())
}

#[test]
fn fixed_page_threshold_protects_every_window_and_every_page_once() -> Test {
    let mut p = LocalRootPublisher::open(fresh("multiple")?, storage_limits())?;
    let mut w = open(&mut p)?; let mut pins = Vec::new();
    for i in 0..3 { offer(&mut w, i * 3600)?; pins.extend(drain(&mut w)?); }
    w.finish(2)?; pins.extend(drain(&mut w)?);
    assert_eq!(pins.len(), 5); // three original windows plus full/final-partial catalog pages
    assert_eq!(w.snapshot().windows().len(), 3); assert_eq!(w.snapshot().indexed_windows(), 3);
    assert_eq!(w.snapshot().pages().len(), 2);
    assert!(matches!(w.step(2000, &Cancel)?, CheckpointedArchiveProgress::Archive(ArchiveWriteProgress::Exhausted)));
    Ok(())
}

#[test]
fn cancellation_after_pin_ack_fences_without_losing_input_or_candidate() -> Test {
    let mut p = LocalRootPublisher::open(fresh("cancel")?, storage_limits())?;
    let mut w = open(&mut p)?; let root = offer(&mut w, 0)?; let pin = pin(&mut w)?;
    w.acknowledge_checkpoint(&pin, 2, &NeverCancel)?;
    assert!(matches!(w.step(2, &Cancel), Err(ArchiveError::Cancelled)));
    assert!(matches!(w.step(2, &NeverCancel), Err(ArchiveError::Blocked)));
    let retired = w.retire(); assert_eq!(retired.pending_checkpoint, Some(pin));
    assert_eq!(retired.archive.pending.ok_or("source lost")?.manifest().root(), root);
    assert!(p.root(&namespace()?.window_slot(0)?).is_none()); Ok(())
}

#[test]
fn checkpoint_publication_failure_never_advances_normal_archive_and_preserves_exact_work() -> Test {
    for (i, cut) in [PublishCutPoint::AfterChildrenVerified, PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite, PublishCutPoint::AfterRootRename].into_iter().enumerate() {
        let path = fresh(&format!("cut_{i}"))?;
        {
            let mut p = LocalRootPublisher::open(&path, storage_limits())?; p.inject_crash_at(cut);
            let mut w = open(&mut p)?; let root = offer(&mut w, 0)?; let pin = pin(&mut w)?;
            w.acknowledge_checkpoint(&pin, 2, &NeverCancel)?;
            assert!(w.step(2, &NeverCancel).is_err());
            assert!(matches!(w.step(2, &NeverCancel), Err(ArchiveError::Blocked)));
            assert!(w.snapshot().windows().is_empty());
            let retired = w.retire(); assert_eq!(retired.pending_checkpoint, Some(pin));
            assert!(retired.last_durable_checkpoint.is_none());
            assert_eq!(retired.archive.pending.ok_or("source lost")?.manifest().root(), root);
        }
        let p = LocalRootPublisher::open(&path, storage_limits())?;
        assert!(p.root(&namespace()?.window_slot(0)?).is_none());
    }
    Ok(())
}

#[test]
fn byte_graph_and_work_budgets_refuse_without_weakening_the_barrier() -> Test {
    let mut p = LocalRootPublisher::open(fresh("bytes")?, storage_limits())?;
    let mut w = CheckpointedArchiveWriter::open(&mut p, namespace()?, limits(),
        ArchiveWorkLimits { max_pending_bytes: 1, ..ArchiveWorkLimits::default() }, 10, 0, 1000, &NeverCancel)?;
    let window = window(0)?; let root = window.manifest().root(); let bytes = window.byte_len();
    let refusal = w.offer(window, bytes, 1).err().ok_or("byte budget ignored")?;
    assert_eq!(refusal.recording.manifest().root(), root); assert!(w.pending().is_none()); drop(w);
    assert_eq!(p.visible_roots().count(), 0);
    for (name, budget) in [("graph", ArchiveWorkLimits { max_graph_objects: 1, ..ArchiveWorkLimits::default() }),
        ("payload", ArchiveWorkLimits { max_new_bytes: 1, ..ArchiveWorkLimits::default() })] {
        let mut p = LocalRootPublisher::open(fresh(name)?, storage_limits())?;
        let mut w = CheckpointedArchiveWriter::open(&mut p, namespace()?, limits(), budget, 10, 0, 1000, &NeverCancel)?;
        offer(&mut w, 0)?; assert!(matches!(w.step(2, &NeverCancel), Err(ArchiveError::Limit)));
        assert!(w.pending().is_some()); assert!(w.pending_checkpoint().is_none());
    }
    Ok(())
}

#[test]
fn pin_waits_and_acknowledgements_cannot_renew_clock_or_step_budget() -> Test {
    let mut p = LocalRootPublisher::open(fresh("clock")?, storage_limits())?;
    let mut w = CheckpointedArchiveWriter::open(&mut p, namespace()?, limits(), ArchiveWorkLimits::default(),
        4, 0, 10, &NeverCancel)?;
    offer(&mut w, 0)?; let checkpoint = pin(&mut w)?; let remaining = w.remaining_steps();
    assert!(matches!(w.step(1, &NeverCancel), Err(ArchiveError::ClockReversed)));
    assert_eq!(w.remaining_steps(), remaining);
    w.acknowledge_checkpoint(&checkpoint, 2, &NeverCancel)?;
    w.acknowledge_checkpoint(&checkpoint, 2, &NeverCancel)?;
    assert!(matches!(w.step(2, &NeverCancel), Err(ArchiveError::Limit)));
    assert!(w.pending().is_some()); drop(w); assert_eq!(p.visible_roots().count(), 0);
    let mut w = open(&mut p)?; offer(&mut w, 0)?; let _ = pin(&mut w)?;
    assert!(matches!(w.step(1000, &NeverCancel), Err(ArchiveError::Deadline)));
    Ok(())
}

#[test]
fn stale_pin_acknowledgement_does_not_unlock_another_checkpoint() -> Test {
    let mut p = LocalRootPublisher::open(fresh("stale_pin")?, storage_limits())?;
    let mut w = open(&mut p)?; offer(&mut w, 0)?; let old = protect(&mut w)?;
    assert!(matches!(w.step(2, &NeverCancel)?, CheckpointedArchiveProgress::Archive(ArchiveWriteProgress::WindowDurable { .. })));
    w.finish(2)?;
    prepare_page(&mut w)?;
    let current = pin(&mut w)?; assert_ne!(current.root(), old.root());
    assert!(matches!(w.acknowledge_checkpoint(&old, 2, &NeverCancel), Err(ArchiveError::Metadata)));
    assert!(matches!(w.step(2, &NeverCancel)?, CheckpointedArchiveProgress::PinRequired(p) if p == current));
    assert_eq!(w.snapshot().indexed_windows(), 0); Ok(())
}

#[test]
fn work_root_lost_ack_uses_the_pin_announced_before_any_checkpoint_write() -> Test {
    let path = fresh("lost_work_ack")?;
    let pin = {
        let mut p = LocalRootPublisher::open(&path, storage_limits())?;
        let mut w = open(&mut p)?; offer(&mut w, 0)?;
        let pin = pin(&mut w)?; w.acknowledge_checkpoint(&pin, 2, &NeverCancel)?;
        // Simulate loss of the WorkDurable reply, not just a normal archive reply.
        let _ = w.step(2, &NeverCancel)?;
        pin
    };
    let p = LocalRootPublisher::open(&path, storage_limits())?;
    let work = load_archive_work(&p, pin.slot(), pin.root(), ArchiveWorkLimits::default(), &NeverCancel)?;
    assert_eq!(archive_retirement_digest(&work)?, pin.retirement_digest());
    assert!(work.snapshot.windows().is_empty()); assert!(work.pending.is_some()); Ok(())
}

#[test]
fn protecting_pending_work_does_not_replace_or_clone_its_media_buffers() -> Test {
    let mut p = LocalRootPublisher::open(fresh("same_buffer")?, storage_limits())?;
    let mut w = open(&mut p)?; offer(&mut w, 0)?;
    let before = w.pending().ok_or("missing window")?.objects();
    let pointers = (before.source.as_ptr(), before.media.as_ptr(), before.index.as_ptr());
    protect(&mut w)?;
    let after = w.pending().ok_or("lost pending window")?.objects();
    assert_eq!(pointers, (after.source.as_ptr(), after.media.as_ptr(), after.index.as_ptr()));
    Ok(())
}

#![forbid(unsafe_code)]
//! Native AVC fixtures, real independent disk journal and existing root-last archive custody.
mod recording_support;
use fss_container::TimedAvcPicture;
use fss_core::ContentDigest;
use fss_ledger::IncompleteTailPolicy;
use fss_object::SpoolLimits;
use fss_publication::{
    LocalPublicationLimits, LocalRootPublisher, NeverCancel, PublishCancellation, PublishCutPoint,
};
use fss_reference::rtsp::archive_pins::*;
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording::{PreparedRecording, RecordingPacket, prepare_recording};
use fss_reference::rtsp::recording_archive::checkpoint::ArchiveWorkLimits;
use fss_reference::rtsp::recording_archive::{
    ArchiveLimits, ArchiveNamespace, ArchiveSnapshot, ArchiveWriteProgress,
};
use fss_reference::rtsp::recording_catalog::CatalogScope;
use recording_support::{Error, fixture, scope};
use std::path::{Path, PathBuf};
type Test<T = ()> = Result<T, Error>;
fn fresh(name: &str) -> Test<PathBuf> {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("archive_pin_pipeline")
        .join(name);
    match std::fs::remove_dir_all(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    std::fs::create_dir_all(&path)?;
    Ok(path)
}
fn limits() -> ArchiveLimits {
    ArchiveLimits {
        max_windows: 8,
        max_pages: 8,
        max_scan_roots: 256,
        windows_per_page: 2,
    }
}
fn storage() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        128,
        1024,
        128,
        1024,
        SpoolLimits::new(1024, 16 * 1024 * 1024, 1024 * 1024, 1024),
    )
}
fn namespace() -> Test<ArchiveNamespace> {
    Ok(ArchiveNamespace::new(CatalogScope {
        recording: scope()?,
        decode_clock: ContentDigest::sha256(b"explicit decode clock"),
        time_scale: 90_000,
    })?)
}
fn pin_scope() -> Test<ArchivePinScope> {
    Ok(ArchivePinScope {
        journal_id: ContentDigest::sha256(b"independently accepted pin epoch"),
        archive_namespace: namespace()?.digest(),
    })
}
fn window(at: u64) -> Test<PreparedRecording> {
    let f = fixture(31, true)?;
    let pictures: Vec<_> = f
        .pictures
        .iter()
        .enumerate()
        .map(|(i, picture)| TimedAvcPicture {
            picture,
            decode_time: at + i as u64 * 3600,
            duration: 3600,
            composition_offset: 0,
        })
        .collect();
    let packets: Vec<_> = f
        .packets
        .iter()
        .map(|(sequence, received_ns, bytes)| RecordingPacket {
            sequence: *sequence,
            received_ns: *received_ns,
            bytes,
        })
        .collect();
    Ok(prepare_recording(scope()?, 90_000, &pictures, &packets)?)
}
fn writer<'a, 'p>(
    publisher: &'a mut LocalRootPublisher,
    pins: &'p mut ArchivePinJournal,
) -> Test<JournaledArchiveWriter<'a, 'p>> {
    Ok(JournaledArchiveWriter::open(
        publisher,
        pins,
        namespace()?,
        limits(),
        ArchiveWorkLimits::default(),
        256,
        0,
        1000,
        &NeverCancel,
    )?)
}
fn offer(w: &mut JournaledArchiveWriter<'_, '_>) -> Test<ContentDigest> {
    let window = window(0)?;
    let root = window.manifest().root();
    let bytes = window.byte_len();
    w.offer(window, bytes, 0)?;
    Ok(root)
}
fn finish(w: &mut JournaledArchiveWriter<'_, '_>) -> Test<(usize, usize)> {
    w.finish(1)?;
    for _ in 0..64 {
        if let JournaledArchiveProgress::Archive(ArchiveWriteProgress::Finished {
            windows,
            pages,
            ..
        }) = w.step(1, &NeverCancel)?
        {
            return Ok((windows, pages));
        }
    }
    Err("bounded pin/recording/page drain did not finish".into())
}
fn publish_original(p: &mut LocalRootPublisher, window: &PreparedRecording) -> Test {
    let mut job = RecordingPublication::new(
        window,
        p,
        namespace()?.window_slot(0)?,
        window.byte_len(),
        1000,
    )?;
    for _ in 0..5 {
        if matches!(job.step(0, &NeverCancel)?, RecordingProgress::Published(_)) {
            return Ok(());
        }
    }
    Err("original window did not publish".into())
}
#[test]
fn both_window_and_catalog_automatically_journal_before_normal_publication() -> Test {
    let path = fresh("complete")?;
    let (anchor, expected_root, source) = {
        let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
        let mut pins = ArchivePinJournal::create(
            path.join("pins"),
            pin_scope()?,
            ArchivePinLimits::default(),
            &NeverCancel,
        )?;
        let mut w = writer(&mut p, &mut pins)?;
        let root = offer(&mut w)?;
        let source = w.pending().ok_or("pending")?.objects().source.to_vec();
        assert!(
            matches!(w.step(0, &NeverCancel)?, JournaledArchiveProgress::PinPersisted { receipt, .. }
            if receipt.phase() == ArchivePinPhase::Candidate && receipt.anchor().sequence == 2)
        );
        assert_eq!(w.snapshot().windows().len(), 0);
        assert!(
            matches!(w.step(0, &NeverCancel)?, JournaledArchiveProgress::WorkConfirmed { pin_receipt, .. }
            if pin_receipt.phase() == ArchivePinPhase::Confirmed && pin_receipt.anchor().sequence == 3)
        );
        assert_eq!(w.snapshot().windows().len(), 0);
        assert!(matches!(
            w.step(0, &NeverCancel)?,
            JournaledArchiveProgress::Archive(ArchiveWriteProgress::WindowDurable {
                ordinal: 0,
                ..
            })
        ));
        assert_eq!(finish(&mut w)?, (1, 1));
        assert_eq!(w.journal_anchor().sequence, 5);
        let retired = w.retire();
        assert!(retired.unrecorded_confirmation.is_none());
        pins.require_settled(&p, ArchiveWorkLimits::default(), &NeverCancel)?;
        (pins.anchor(), root, source)
    };
    let p = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = ArchivePinJournal::open_existing(
        path.join("pins"),
        pin_scope()?,
        Some(anchor),
        ArchivePinLimits::default(),
        IncompleteTailPolicy::Reject,
        &NeverCancel,
    )?;
    pins.require_settled(&p, ArchiveWorkLimits::default(), &NeverCancel)?;
    let snapshot = ArchiveSnapshot::load(&p, namespace()?, limits(), &NeverCancel)?;
    assert_eq!(snapshot.windows()[0].root(), expected_root);
    assert_eq!(snapshot.indexed_windows(), 1);
    let journal = std::fs::read(path.join("pins/pins.journal"))?;
    assert!(!journal.windows(source.len()).any(|b| b == source));
    Ok(())
}
#[test]
fn confirmed_auxiliary_work_cannot_be_forgotten_on_new_writer_startup() -> Test {
    let path = fresh("confirmed_not_archived")?;
    let anchor = {
        let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
        let mut pins = ArchivePinJournal::create(
            path.join("pins"),
            pin_scope()?,
            ArchivePinLimits::default(),
            &NeverCancel,
        )?;
        let mut w = writer(&mut p, &mut pins)?;
        offer(&mut w)?;
        let _ = w.step(0, &NeverCancel)?;
        let _ = w.step(0, &NeverCancel)?;
        assert!(w.pin_state().candidate().is_none());
        assert_eq!(w.snapshot().windows().len(), 0);
        w.journal_anchor()
    }; // Entire process state lost; source work and independent reference already committed.
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = ArchivePinJournal::open_existing(
        path.join("pins"),
        pin_scope()?,
        Some(anchor),
        ArchivePinLimits::default(),
        IncompleteTailPolicy::Reject,
        &NeverCancel,
    )?;
    assert!(matches!(
        pins.require_settled(&p, ArchiveWorkLimits::default(), &NeverCancel),
        Err(ArchivePinError::Unsettled)
    ));
    let work = pins.load_work(
        ArchivePinPhase::Confirmed,
        &p,
        ArchiveWorkLimits::default(),
        &NeverCancel,
    )?;
    publish_original(
        &mut p,
        work.pending.as_ref().ok_or("recovery lost original")?,
    )?;
    pins.require_settled(&p, ArchiveWorkLimits::default(), &NeverCancel)?;
    let mut w = writer(&mut p, &mut pins)?;
    assert_eq!(finish(&mut w)?, (1, 1));
    Ok(())
}
#[test]
fn candidate_without_committed_source_remains_an_explicit_recovery_obligation() -> Test {
    let path = fresh("uncommitted_candidate")?;
    {
        let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
        let mut pins = ArchivePinJournal::create(
            path.join("pins"),
            pin_scope()?,
            ArchivePinLimits::default(),
            &NeverCancel,
        )?;
        let mut w = writer(&mut p, &mut pins)?;
        offer(&mut w)?;
        let _ = w.step(0, &NeverCancel)?;
    }
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = ArchivePinJournal::open_existing(
        path.join("pins"),
        pin_scope()?,
        None,
        ArchivePinLimits::default(),
        IncompleteTailPolicy::Reject,
        &NeverCancel,
    )?;
    assert!(pins.state().candidate().is_some());
    assert!(
        pins.load_work(
            ArchivePinPhase::Candidate,
            &p,
            ArchiveWorkLimits::default(),
            &NeverCancel
        )
        .is_err()
    );
    assert!(writer(&mut p, &mut pins).is_err());
    assert!(p.visible_roots().next().is_none());
    Ok(())
}
#[test]
fn confirmation_capacity_failure_preserves_work_and_blocks_normal_window_publication() -> Test {
    let path = fresh("confirm_limit")?;
    {
        let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
        let mut pins = ArchivePinJournal::create(
            path.join("pins"),
            pin_scope()?,
            ArchivePinLimits {
                max_records: 2,
                ..ArchivePinLimits::default()
            },
            &NeverCancel,
        )?;
        let mut w = writer(&mut p, &mut pins)?;
        let root = offer(&mut w)?;
        let _ = w.step(0, &NeverCancel)?;
        assert!(matches!(
            w.step(0, &NeverCancel),
            Err(ArchivePinError::Limit)
        ));
        assert!(matches!(
            w.step(0, &NeverCancel),
            Err(ArchivePinError::Fenced)
        ));
        assert_eq!(w.pending().ok_or("original lost")?.manifest().root(), root);
        let r = w.retire();
        assert!(r.unrecorded_confirmation.is_some());
        assert!(r.writer.archive.snapshot.windows().is_empty());
        assert!(p.root(&namespace()?.window_slot(0)?).is_none());
    }
    let p = LocalRootPublisher::open(path.join("media"), storage())?;
    // A new, explicitly supplied larger budget permits metadata-only reconciliation.
    let mut pins = ArchivePinJournal::open_existing(
        path.join("pins"),
        pin_scope()?,
        None,
        ArchivePinLimits::default(),
        IncompleteTailPolicy::Reject,
        &NeverCancel,
    )?;
    let receipt = pins.confirm_recovered(&p, ArchiveWorkLimits::default(), &NeverCancel)?;
    assert_eq!(receipt.phase(), ArchivePinPhase::Confirmed);
    assert!(matches!(
        pins.require_settled(&p, ArchiveWorkLimits::default(), &NeverCancel),
        Err(ArchivePinError::Unsettled)
    ));
    Ok(())
}
#[test]
fn corrupt_pin_tip_fences_before_source_checkpoint_and_returns_original_input() -> Test {
    let path = fresh("tip_corruption")?;
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = ArchivePinJournal::create(
        path.join("pins"),
        pin_scope()?,
        ArchivePinLimits::default(),
        &NeverCancel,
    )?;
    let mut w = writer(&mut p, &mut pins)?;
    let root = offer(&mut w)?;
    let file = path.join("pins/pins.journal");
    let mut data = std::fs::read(&file)?;
    let last = data.last_mut().ok_or("empty journal")?;
    *last ^= 1;
    std::fs::write(file, data)?;
    assert!(w.step(0, &NeverCancel).is_err());
    let retired = w.retire();
    assert_eq!(
        retired
            .writer
            .archive
            .pending
            .ok_or("lost source")?
            .manifest()
            .root(),
        root
    );
    assert!(p.visible_roots().next().is_none());
    Ok(())
}
#[test]
fn wrong_journal_namespace_refuses_without_touching_either_store() -> Test {
    let path = fresh("wrong_namespace")?;
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let wrong = ArchivePinScope {
        archive_namespace: ContentDigest::sha256(b"other camera"),
        ..pin_scope()?
    };
    let mut pins = ArchivePinJournal::create(
        path.join("pins"),
        wrong,
        ArchivePinLimits::default(),
        &NeverCancel,
    )?;
    let anchor = pins.anchor();
    assert!(writer(&mut p, &mut pins).is_err());
    assert_eq!(pins.anchor(), anchor);
    assert!(p.visible_roots().next().is_none());
    Ok(())
}
#[test]
fn clock_reversal_is_safe_but_expiry_never_bypasses_a_persisted_candidate() -> Test {
    let path = fresh("time")?;
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = ArchivePinJournal::create(
        path.join("pins"),
        pin_scope()?,
        ArchivePinLimits::default(),
        &NeverCancel,
    )?;
    let mut w = writer(&mut p, &mut pins)?;
    offer(&mut w)?;
    let _ = w.step(10, &NeverCancel)?;
    let anchor = w.journal_anchor();
    assert!(matches!(
        w.step(9, &NeverCancel),
        Err(ArchivePinError::Archive(
            fss_reference::rtsp::recording_archive::ArchiveError::ClockReversed
        ))
    ));
    assert_eq!(w.journal_anchor(), anchor);
    assert!(w.step(1000, &NeverCancel).is_err());
    let r = w.retire();
    assert!(r.pins.candidate().is_some());
    assert!(r.writer.archive.pending.is_some());
    assert!(p.visible_roots().next().is_none());
    Ok(())
}
#[test]
fn cancellation_does_not_unlock_work_or_erase_accepted_source() -> Test {
    struct Cancel;
    impl PublishCancellation for Cancel {
        fn cancel_requested(&self, _: PublishCutPoint) -> bool {
            true
        }
    }
    let path = fresh("cancel")?;
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = ArchivePinJournal::create(
        path.join("pins"),
        pin_scope()?,
        ArchivePinLimits::default(),
        &NeverCancel,
    )?;
    let mut w = writer(&mut p, &mut pins)?;
    let root = offer(&mut w)?;
    assert!(matches!(
        w.step(0, &Cancel),
        Err(ArchivePinError::Cancelled)
    ));
    let retired = w.retire();
    assert_eq!(
        retired
            .writer
            .archive
            .pending
            .ok_or("lost source")?
            .manifest()
            .root(),
        root
    );
    assert!(p.visible_roots().next().is_none());
    Ok(())
}

#[path = "archive_pin_pipeline/live.rs"]
mod live;
#[path = "archive_pin_pipeline/restoration.rs"]
mod restoration;

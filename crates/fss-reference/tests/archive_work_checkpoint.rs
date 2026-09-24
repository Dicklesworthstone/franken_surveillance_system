#![forbid(unsafe_code)]
//! Native source-linked recordings and real local publication; no replacement persistence model.
mod recording_support;
use fss_container::TimedAvcPicture;
use fss_core::ContentDigest;
use fss_object::SpoolLimits;
use fss_publication::{
    LocalPublicationLimits, LocalRootPublisher, NeverCancel, PublishCancellation, PublishCutPoint,
    PublishOutcome, SlotName,
};
use fss_reference::rtsp::archive_recovery::{
    ArchiveResumeConfig, ArchiveResumeProgress, RecordingArchiveResume, RetiredPublicationState,
    archive_retirement_digest,
};
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording::{PreparedRecording, RecordingPacket, prepare_recording};
use fss_reference::rtsp::recording_archive::checkpoint::{
    ArchiveWorkLimits, PreparedArchiveWork, load_archive_work,
};
use fss_reference::rtsp::recording_archive::{
    ArchiveLimits, ArchiveNamespace, ArchiveRetirement, ArchiveSnapshot, ArchiveWriteProgress,
    RecordingArchiveWriter,
};
use fss_reference::rtsp::recording_catalog::CatalogScope;
use recording_support::{Error, fixture, scope};
use std::path::{Path, PathBuf};

type Test = Result<(), Error>;
fn fresh(name: &str) -> Result<PathBuf, Error> {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("archive_work_checkpoint")
        .join(name);
    match std::fs::remove_dir_all(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(path)
}
fn storage_limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        128,
        1024,
        128,
        1024,
        SpoolLimits::new(1024, 16 * 1024 * 1024, 1024 * 1024, 1024),
    )
}
fn limits() -> ArchiveLimits {
    ArchiveLimits {
        max_windows: 8,
        max_pages: 8,
        max_scan_roots: 256,
        windows_per_page: 2,
    }
}
fn namespace() -> Result<ArchiveNamespace, Error> {
    Ok(ArchiveNamespace::new(CatalogScope {
        recording: scope()?,
        decode_clock: ContentDigest::sha256(b"explicit recording decode clock"),
        time_scale: 90_000,
    })?)
}
fn window(at: u64) -> Result<PreparedRecording, Error> {
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
fn pending(p: &mut LocalRootPublisher) -> Result<ArchiveRetirement, Error> {
    let mut w = RecordingArchiveWriter::open(p, namespace()?, limits(), 0, 1000, &NeverCancel)?;
    let recording = window(0)?;
    let bytes = recording.byte_len();
    w.offer(recording, bytes, 0)?;
    Ok(w.retire())
}
fn save(
    p: &mut LocalRootPublisher,
    work: &ArchiveRetirement,
) -> Result<(SlotName, ContentDigest), Error> {
    let plan = PreparedArchiveWork::prepare(work, p, ArchiveWorkLimits::default(), &NeverCancel)?;
    // In a runtime these two values must be pinned independently before this attempted write.
    let pin = (plan.slot().clone(), plan.root());
    assert_eq!(plan.publish(p, 1, 1000, &NeverCancel)?.root, pin.1);
    Ok(pin)
}
fn drain(p: &mut LocalRootPublisher, work: ArchiveRetirement) -> Result<usize, Error> {
    let digest = archive_retirement_digest(&work)?;
    let mut resume = RecordingArchiveResume::open(
        p,
        work,
        ArchiveResumeConfig {
            expected_retirement_digest: digest,
            max_window_bytes: 1024 * 1024,
            max_steps: 100,
            deadline_ns: 1000,
        },
        2,
        &NeverCancel,
    )?;
    for _ in 0..100 {
        if let ArchiveResumeProgress::Archive(ArchiveWriteProgress::Finished { windows, .. }) =
            resume.step(2, &NeverCancel)?
        {
            return Ok(windows);
        }
    }
    Err("bounded storage-only recovery did not finish".into())
}
fn publish_window(p: &mut LocalRootPublisher, w: &PreparedRecording, ordinal: usize) -> Test {
    let mut job =
        RecordingPublication::new(w, p, namespace()?.window_slot(ordinal)?, w.byte_len(), 1000)?;
    for _ in 0..5 {
        if matches!(job.step(2, &NeverCancel)?, RecordingProgress::Published(_)) {
            return Ok(());
        }
    }
    Err("recording was not published".into())
}
struct Cancel;
impl PublishCancellation for Cancel {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        true
    }
}

#[test]
fn cold_restart_recovers_original_bytes_without_original_rust_objects() -> Test {
    let path = fresh("cold")?;
    let (pin, expected, source, media, index, old_digest) = {
        let mut p = LocalRootPublisher::open(&path, storage_limits())?;
        let work = pending(&mut p)?;
        let w = work.pending.as_ref().ok_or("missing pending window")?;
        let expected = w.manifest().root();
        let objects = w.objects();
        let digests = (
            ContentDigest::sha256(objects.source),
            ContentDigest::sha256(objects.media),
            ContentDigest::sha256(objects.index),
        );
        let digest = archive_retirement_digest(&work)?;
        let pin = save(&mut p, &work)?;
        assert!(
            ArchiveSnapshot::load(&p, namespace()?, limits(), &NeverCancel)?
                .windows()
                .is_empty()
        );
        (pin, expected, digests.0, digests.1, digests.2, digest)
    }; // Drop every prepared recording, archive retirement and publisher.
    let mut p = LocalRootPublisher::open(&path, storage_limits())?;
    let work = load_archive_work(
        &p,
        &pin.0,
        pin.1,
        ArchiveWorkLimits::default(),
        &NeverCancel,
    )?;
    assert_eq!(archive_retirement_digest(&work)?, old_digest);
    let w = work.pending.as_ref().ok_or("pending window lost")?;
    assert_eq!(w.manifest().root(), expected);
    assert_eq!(ContentDigest::sha256(w.objects().source), source);
    assert_eq!(ContentDigest::sha256(w.objects().media), media);
    assert_eq!(ContentDigest::sha256(w.objects().index), index);
    assert_eq!(drain(&mut p, work)?, 1);
    let snapshot = ArchiveSnapshot::load(&p, namespace()?, limits(), &NeverCancel)?;
    assert_eq!(snapshot.indexed_windows(), 1);
    assert_eq!(snapshot.windows()[0].root(), expected);
    Ok(())
}

#[test]
fn old_prepared_page_and_next_unoffered_window_both_survive_cold_restart() -> Test {
    let path = fresh("page_and_next")?;
    let (pin, first, second, page_root) = {
        let mut p = LocalRootPublisher::open(&path, storage_limits())?;
        let mut w =
            RecordingArchiveWriter::open(&mut p, namespace()?, limits(), 0, 1000, &NeverCancel)?;
        let first = window(0)?;
        let root = first.manifest().root();
        let bytes = first.byte_len();
        w.offer(first, bytes, 0)?;
        assert!(matches!(
            w.step(1, &NeverCancel)?,
            ArchiveWriteProgress::WindowDurable { .. }
        ));
        w.flush();
        for _ in 0..3 {
            w.step(1, &NeverCancel)?;
        }
        let mut work = w.retire();
        let page_root = work
            .prepared_page
            .as_ref()
            .ok_or("page missing")?
            .manifest()
            .root();
        let next = window(3600)?;
        let second = next.manifest().root();
        work.pending = Some(next);
        (save(&mut p, &work)?, root, second, page_root)
    };
    let mut p = LocalRootPublisher::open(&path, storage_limits())?;
    let work = load_archive_work(
        &p,
        &pin.0,
        pin.1,
        ArchiveWorkLimits::default(),
        &NeverCancel,
    )?;
    assert_eq!(
        work.prepared_page
            .as_ref()
            .ok_or("lost page")?
            .manifest()
            .root(),
        page_root
    );
    assert_eq!(drain(&mut p, work)?, 2);
    let snapshot = ArchiveSnapshot::load(&p, namespace()?, limits(), &NeverCancel)?;
    assert_eq!(
        snapshot
            .windows()
            .iter()
            .map(|w| w.root())
            .collect::<Vec<_>>(),
        vec![first, second]
    );
    assert_eq!(snapshot.pages()[0].catalog().manifest().root(), page_root);
    assert_eq!(snapshot.indexed_windows(), 2);
    Ok(())
}

#[test]
fn repeated_save_does_not_allocate_an_archive_ordinal_or_duplicate_custody_roots() -> Test {
    let mut p = LocalRootPublisher::open(fresh("repeat")?, storage_limits())?;
    let work = pending(&mut p)?;
    let plan = PreparedArchiveWork::prepare(&work, &p, ArchiveWorkLimits::default(), &NeverCancel)?;
    plan.publish(&mut p, 1, 1000, &NeverCancel)?;
    let count = p.visible_roots().count();
    assert_eq!(
        plan.publish(&mut p, 2, 1000, &NeverCancel)?.outcome,
        PublishOutcome::AlreadyPublished
    );
    assert_eq!(p.visible_roots().count(), count);
    assert!(
        ArchiveSnapshot::load(&p, namespace()?, limits(), &NeverCancel)?
            .windows()
            .is_empty()
    );
    Ok(())
}

#[test]
fn window_committed_after_checkpoint_is_reconciled_without_a_second_ordinal() -> Test {
    let path = fresh("window_ack")?;
    let pin = {
        let mut p = LocalRootPublisher::open(&path, storage_limits())?;
        let work = pending(&mut p)?;
        let pin = save(&mut p, &work)?;
        publish_window(&mut p, work.pending.as_ref().ok_or("missing window")?, 0)?;
        pin
    };
    let mut p = LocalRootPublisher::open(&path, storage_limits())?;
    let work = load_archive_work(
        &p,
        &pin.0,
        pin.1,
        ArchiveWorkLimits::default(),
        &NeverCancel,
    )?;
    let digest = archive_retirement_digest(&work)?;
    let mut resume = RecordingArchiveResume::open(
        &mut p,
        work,
        ArchiveResumeConfig {
            expected_retirement_digest: digest,
            max_window_bytes: 1024 * 1024,
            max_steps: 100,
            deadline_ns: 1000,
        },
        2,
        &NeverCancel,
    )?;
    assert!(matches!(
        resume.reconciliation().window,
        RetiredPublicationState::AlreadyDurable(_)
    ));
    for _ in 0..100 {
        let step = resume.step(2, &NeverCancel)?;
        assert!(!matches!(step, ArchiveResumeProgress::WindowAccepted(_)));
        if let ArchiveResumeProgress::Archive(ArchiveWriteProgress::Finished { windows, .. }) = step
        {
            assert_eq!(windows, 1);
            return Ok(());
        }
    }
    Err("resume did not finish".into())
}

#[test]
fn each_root_cut_distinguishes_unpublished_work_from_a_lost_final_ack() -> Test {
    for (i, cut) in [
        PublishCutPoint::AfterChildrenVerified,
        PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite,
        PublishCutPoint::AfterRootRename,
    ]
    .into_iter()
    .enumerate()
    {
        let path = fresh(&format!("cut_{i}"))?;
        let pin = {
            let mut p = LocalRootPublisher::open(&path, storage_limits())?;
            let work = RecordingArchiveWriter::open(
                &mut p,
                namespace()?,
                limits(),
                0,
                1000,
                &NeverCancel,
            )?
            .retire();
            let plan = PreparedArchiveWork::prepare(
                &work,
                &p,
                ArchiveWorkLimits::default(),
                &NeverCancel,
            )?;
            let pin = (plan.slot().clone(), plan.root());
            p.inject_crash_at(cut);
            assert!(plan.publish(&mut p, 1, 1000, &NeverCancel).is_err());
            pin
        };
        let p = LocalRootPublisher::open(&path, storage_limits())?;
        let result = load_archive_work(
            &p,
            &pin.0,
            pin.1,
            ArchiveWorkLimits::default(),
            &NeverCancel,
        );
        if cut == PublishCutPoint::AfterRootRename {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }
    Ok(())
}

#[test]
fn cancellation_and_resource_refusals_preserve_work_without_publishing() -> Test {
    let mut p = LocalRootPublisher::open(fresh("denied")?, storage_limits())?;
    let work = pending(&mut p)?;
    let root = work
        .pending
        .as_ref()
        .ok_or("missing window")?
        .manifest()
        .root();
    for bounds in [
        ArchiveWorkLimits {
            max_pending_bytes: 0,
            ..ArchiveWorkLimits::default()
        },
        ArchiveWorkLimits {
            max_graph_objects: 1,
            ..ArchiveWorkLimits::default()
        },
        ArchiveWorkLimits {
            max_new_bytes: 0,
            ..ArchiveWorkLimits::default()
        },
    ] {
        assert!(PreparedArchiveWork::prepare(&work, &p, bounds, &NeverCancel).is_err());
    }
    let plan = PreparedArchiveWork::prepare(&work, &p, ArchiveWorkLimits::default(), &NeverCancel)?;
    assert!(plan.publish(&mut p, 1, 1000, &Cancel).is_err());
    assert!(plan.publish(&mut p, 1000, 1000, &NeverCancel).is_err());
    assert_eq!(p.visible_roots().count(), 0);
    assert_eq!(
        work.pending
            .as_ref()
            .ok_or("lost window")?
            .manifest()
            .root(),
        root
    );
    Ok(())
}

#[test]
fn current_unaccounted_extra_recordings_are_not_silently_adopted() -> Test {
    let mut p = LocalRootPublisher::open(fresh("extra")?, storage_limits())?;
    let work = pending(&mut p)?;
    let pin = save(&mut p, &work)?;
    publish_window(&mut p, work.pending.as_ref().ok_or("missing window")?, 0)?;
    publish_window(&mut p, &window(3600)?, 1)?;
    assert!(
        load_archive_work(
            &p,
            &pin.0,
            pin.1,
            ArchiveWorkLimits::default(),
            &NeverCancel
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn wrong_pin_tighter_external_limits_and_revoked_read_are_refused() -> Test {
    let mut p = LocalRootPublisher::open(fresh("pins")?, storage_limits())?;
    let work = pending(&mut p)?;
    let pin = save(&mut p, &work)?;
    assert!(
        load_archive_work(
            &p,
            &pin.0,
            ContentDigest::sha256(b"wrong pin"),
            ArchiveWorkLimits::default(),
            &NeverCancel
        )
        .is_err()
    );
    let mut bounds = ArchiveWorkLimits::default();
    bounds.archive.max_windows = 1;
    assert!(load_archive_work(&p, &pin.0, pin.1, bounds, &NeverCancel).is_err());
    assert!(load_archive_work(&p, &pin.0, pin.1, ArchiveWorkLimits::default(), &Cancel).is_err());
    Ok(())
}

#[test]
fn corrupt_checkpointed_source_is_not_resurrected_or_replaced() -> Test {
    let path = fresh("corrupt")?;
    let (pin, source) = {
        let mut p = LocalRootPublisher::open(&path, storage_limits())?;
        let work = pending(&mut p)?;
        let source = work.pending.as_ref().ok_or("missing window")?.children()[0].1;
        (save(&mut p, &work)?, source)
    };
    let text = source.to_text();
    let object = path
        .join("spool")
        .join("objects")
        .join(text.strip_prefix("sha256:").ok_or("algorithm")?);
    let mut bytes = std::fs::read(&object)?;
    *bytes.last_mut().ok_or("empty spool object")? ^= 1;
    std::fs::write(object, bytes)?;
    if let Ok(p) = LocalRootPublisher::open(&path, storage_limits()) {
        assert!(
            load_archive_work(
                &p,
                &pin.0,
                pin.1,
                ArchiveWorkLimits::default(),
                &NeverCancel
            )
            .is_err()
        );
    }
    Ok(())
}

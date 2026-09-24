#![forbid(unsafe_code)]
//! Real storage owners, exact source replay, and fail-closed range completion.
mod hevc_catalog_support;
mod hevc_recording_support;
mod recording_support;

use fss_core::ContentDigest;
use fss_object::{ObjectManifest, SpoolLimits};
use fss_publication::{
    LocalPublicationLimits, LocalPublicationState, LocalRootPublisher, NeverCancel,
    PublishCancellation, PublishCutPoint, PublishOutcome, SlotName,
};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording::hevc::HEVC_RECORDING_KIND;
use fss_reference::rtsp::recording::local::{
    RecordingIoError, RecordingProgress, RecordingPublication,
};
use fss_reference::rtsp::recording_catalog::hevc::local::{
    HevcCatalogPublication, HevcRangeProgress as P, HevcRecordingRangeRead, load_hevc_catalog,
};
use fss_reference::rtsp::recording_catalog::hevc::{
    HEVC_CATALOG_KIND, HevcCatalogWindow, HevcRecordingCatalog, prepare_hevc_catalog,
    verify_hevc_catalog,
};
use fss_reference::rtsp::recording_catalog::local::{
    CatalogIoError as E, CatalogProgress, CatalogPublication, RangeProgress, RecordingRangeRead,
    load_catalog,
};
use fss_reference::rtsp::recording_catalog::{
    CatalogBuilder, CatalogError, CatalogQueryLimits, CatalogScope,
};
use hevc_catalog_support::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

type TestResult = Result<(), Error>;
fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        16,
        512,
        16,
        128,
        SpoolLimits::new(128, 32 * 1024 * 1024, 1024 * 1024, 256),
    )
}
fn fresh(name: &str) -> Result<PathBuf, Error> {
    let p = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("hevc_catalog_local_contract")
        .join(name);
    match std::fs::remove_dir_all(&p) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(p)
}
fn catalog_slot() -> Result<SlotName, Error> {
    Ok(SlotName::parse("hevc-catalog")?)
}
fn publish_window(
    p: &mut LocalRootPublisher,
    slot: &SlotName,
    plan: &PreparedRecording,
) -> TestResult {
    let mut job = RecordingPublication::new(plan, p, slot.clone(), plan.byte_len(), 100)?;
    for i in 0..4 {
        assert!(matches!(
            job.step(i, &NeverCancel)?,
            RecordingProgress::ChildStaged { .. }
        ));
    }
    assert!(matches!(
        job.step(4, &NeverCancel)?,
        RecordingProgress::Published(_)
    ));
    Ok(())
}
fn setup(name: &str) -> Result<(PathBuf, LocalRootPublisher, HevcRecordingCatalog), Error> {
    let path = fresh(name)?;
    let mut p = LocalRootPublisher::open(&path, limits())?;
    let first = window(1_000)?;
    let second = window(100_000)?;
    let a = slot(0)?;
    let b = slot(1)?;
    publish_window(&mut p, &a, first.publication_plan())?;
    publish_window(&mut p, &b, second.publication_plan())?;
    let catalog = prepare_hevc_catalog(
        scope()?,
        &[
            HevcCatalogWindow {
                slot: &a,
                recording: &first,
            },
            HevcCatalogWindow {
                slot: &b,
                recording: &second,
            },
        ],
    )?;
    Ok((path, p, catalog))
}
fn publish(
    p: &mut LocalRootPublisher,
    catalog: &HevcRecordingCatalog,
) -> Result<PublishOutcome, Error> {
    let mut job =
        HevcCatalogPublication::new(catalog, p, catalog_slot()?, catalog.byte_len(), 100)?;
    for i in 0..catalog.entries().len() {
        assert!(
            matches!(job.step(i as u64, &NeverCancel)?, CatalogProgress::WindowVerified { ordinal, .. } if ordinal == i)
        );
    }
    let at = catalog.entries().len() as u64;
    assert!(matches!(
        job.step(at, &NeverCancel)?,
        CatalogProgress::IndexStaged { .. }
    ));
    let CatalogProgress::Published(receipt) = job.step(at + 1, &NeverCancel)? else {
        return Err("no catalog publication receipt".into());
    };
    assert_eq!(receipt.claims.local, LocalPublicationState::Durable);
    assert_eq!(receipt.root, catalog.manifest().root());
    assert!(matches!(
        job.step(at + 2, &NeverCancel)?,
        CatalogProgress::Complete
    ));
    Ok(receipt.outcome)
}
struct Stop;
impl PublishCancellation for Stop {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        true
    }
}
struct Probe {
    count: AtomicUsize,
    stop_at: usize,
}
impl PublishCancellation for Probe {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.count.fetch_add(1, Ordering::SeqCst) + 1 == self.stop_at
    }
}
fn damage(path: &Path, digest: ContentDigest) -> TestResult {
    let text = digest.to_text();
    let hex = text.strip_prefix("sha256:").ok_or("not SHA256")?;
    let file = path.join("spool").join("objects").join(hex);
    let mut bytes = std::fs::read(&file)?;
    let last = bytes.last_mut().ok_or("empty object")?;
    *last ^= 1;
    std::fs::write(file, bytes)?;
    Ok(())
}

#[test]
fn publish_reopen_and_retrieve_exact_hevc_windows_and_boundary_witnesses() -> TestResult {
    let (path, mut p, c) = setup("reopen")?;
    assert_eq!(publish(&mut p, &c)?, PublishOutcome::Published);
    drop(p);
    let p = LocalRootPublisher::open(path, limits())?;
    let slot = catalog_slot()?;
    let loaded = load_hevc_catalog(&p, &slot, c.manifest().root(), &scope()?, &NeverCancel)?;
    assert_eq!(loaded.index_bytes(), c.index_bytes());
    let mut read = HevcRecordingRangeRead::new(
        &p,
        &loaded,
        &slot,
        5_000..120_000,
        CatalogQueryLimits::default(),
        100,
    )?;
    for (now, ordinal, base, overlap) in [
        (0, 0, 1_000, 5_000..73_000),
        (1, 1, 100_000, 100_000..120_000),
    ] {
        let P::Window {
            ordinal: got,
            requested_interval,
            recording,
        } = read.step(now, &NeverCancel)?
        else {
            return Err("missing verified HEVC window".into());
        };
        let expected = window(base)?;
        assert_eq!(got, ordinal);
        assert_eq!(requested_interval, overlap);
        assert_eq!(recording.manifest(), expected.manifest());
        assert_eq!(recording.objects().source, expected.objects().source);
        assert_eq!(recording.objects().media, expected.objects().media);
        assert_eq!(recording.mappings(), expected.mappings());
        assert_eq!(recording.samples(), expected.samples());
        assert_eq!(recording.source_only_nals(), expected.source_only_nals());
    }
    let P::Complete(receipt) = read.step(2, &NeverCancel)? else {
        return Err("missing complete receipt".into());
    };
    assert_eq!(receipt.scope, scope()?);
    assert_eq!(receipt.windows, 2);
    assert_eq!(receipt.unindexed, vec![73_000..100_000]);
    assert_eq!(receipt.output_bytes, read.selection().output_bytes());
    assert!(matches!(read.step(100, &Stop)?, P::Exhausted));
    Ok(())
}

#[test]
fn unarchived_window_and_insufficient_reservation_never_publish_a_catalog() -> TestResult {
    let h = window(0)?;
    let a = slot(0)?;
    let c = prepare_hevc_catalog(
        scope()?,
        &[HevcCatalogWindow {
            slot: &a,
            recording: &h,
        }],
    )?;
    let mut p = LocalRootPublisher::open(fresh("not_durable")?, limits())?;
    assert!(matches!(
        HevcCatalogPublication::new(&c, &mut p, catalog_slot()?, c.byte_len() - 1, 100),
        Err(E::Storage(RecordingIoError::Budget))
    ));
    {
        let mut job = HevcCatalogPublication::new(&c, &mut p, catalog_slot()?, c.byte_len(), 100)?;
        assert!(matches!(
            job.step(0, &NeverCancel),
            Err(E::Storage(RecordingIoError::NotDurable))
        ));
        assert!(matches!(
            job.step(1, &NeverCancel),
            Err(E::Storage(RecordingIoError::Stopped))
        ));
    }
    assert!(p.root(&catalog_slot()?).is_none());
    publish_window(&mut p, &a, h.publication_plan())?;
    assert_eq!(publish(&mut p, &c)?, PublishOutcome::Published);
    Ok(())
}

#[test]
fn cancellation_after_index_stage_keeps_exact_retry_and_existing_windows() -> TestResult {
    let (_, mut p, c) = setup("cancel_stage")?;
    {
        let mut job = HevcCatalogPublication::new(&c, &mut p, catalog_slot()?, c.byte_len(), 100)?;
        for i in 0..3 {
            job.step(i, &NeverCancel)?;
        }
        assert!(matches!(
            job.step(3, &Stop),
            Err(E::Storage(RecordingIoError::Cancelled))
        ));
    }
    assert!(p.root(&catalog_slot()?).is_none());
    assert_eq!(p.visible_roots().count(), 2);
    assert_eq!(publish(&mut p, &c)?, PublishOutcome::Published);
    assert_eq!(publish(&mut p, &c)?, PublishOutcome::AlreadyPublished);
    assert_eq!(p.visible_roots().count(), 3);
    Ok(())
}

#[test]
fn crash_cut_points_keep_partial_catalogs_hidden_and_recover_lost_receipts() -> TestResult {
    for (i, cut) in [
        PublishCutPoint::AfterChildrenVerified,
        PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite,
        PublishCutPoint::AfterRootRename,
    ]
    .into_iter()
    .enumerate()
    {
        let (path, mut p, c) = setup(&format!("crash_{i}"))?;
        p.inject_crash_at(cut);
        {
            let mut job =
                HevcCatalogPublication::new(&c, &mut p, catalog_slot()?, c.byte_len(), 100)?;
            for at in 0..3 {
                job.step(at, &NeverCancel)?;
            }
            assert!(job.step(3, &NeverCancel).is_err());
        }
        assert!(matches!(
            load_hevc_catalog(
                &p,
                &catalog_slot()?,
                c.manifest().root(),
                &scope()?,
                &NeverCancel
            ),
            Err(E::Storage(RecordingIoError::ReopenRequired))
        ));
        drop(p);
        let mut reopened = LocalRootPublisher::open(path, limits())?;
        match cut {
            PublishCutPoint::AfterRootRename => {
                assert_eq!(
                    publish(&mut reopened, &c)?,
                    PublishOutcome::AlreadyPublished
                );
                load_hevc_catalog(
                    &reopened,
                    &catalog_slot()?,
                    c.manifest().root(),
                    &scope()?,
                    &NeverCancel,
                )?;
            }
            PublishCutPoint::AfterRootTempWrite => {
                assert!(reopened.root(&catalog_slot()?).is_none());
                assert!(!reopened.recovery_report().orphaned_temps.is_empty());
                assert!(publish(&mut reopened, &c).is_err());
            }
            _ => {
                assert!(reopened.root(&catalog_slot()?).is_none());
                assert_eq!(publish(&mut reopened, &c)?, PublishOutcome::Published);
            }
        }
    }
    Ok(())
}

#[test]
fn cancellation_at_every_window_disclosure_check_never_returns_the_window() -> TestResult {
    let (_, mut p, c) = setup("cancel_read")?;
    publish(&mut p, &c)?;
    let slot = catalog_slot()?;
    let counter = Probe {
        count: AtomicUsize::new(0),
        stop_at: usize::MAX,
    };
    let mut baseline = HevcRecordingRangeRead::new(
        &p,
        &c,
        &slot,
        1_001..1_002,
        CatalogQueryLimits::default(),
        100,
    )?;
    assert!(matches!(baseline.step(0, &counter)?, P::Window { .. }));
    let checks = counter.count.load(Ordering::SeqCst);
    assert!(checks > 5);
    for stop_at in 1..=checks {
        let mut read = HevcRecordingRangeRead::new(
            &p,
            &c,
            &slot,
            1_001..1_002,
            CatalogQueryLimits::default(),
            100,
        )?;
        let probe = Probe {
            count: AtomicUsize::new(0),
            stop_at,
        };
        assert!(matches!(
            read.step(0, &probe),
            Err(E::Storage(RecordingIoError::Cancelled))
        ));
        assert_eq!(read.returned_windows(), 0);
        assert!(matches!(
            read.step(1, &NeverCancel),
            Err(E::Storage(RecordingIoError::Stopped))
        ));
    }
    Ok(())
}

#[test]
fn later_cancellation_deadline_and_clock_reversal_do_not_fake_completion() -> TestResult {
    let (_, mut p, c) = setup("partial")?;
    publish(&mut p, &c)?;
    let slot = catalog_slot()?;
    let mut read =
        HevcRecordingRangeRead::new(&p, &c, &slot, 0..200_000, CatalogQueryLimits::default(), 10)?;
    let first = read.step(5, &NeverCancel)?;
    assert!(matches!(&first, P::Window { ordinal: 0, .. }));
    assert!(matches!(
        read.step(4, &NeverCancel),
        Err(E::Storage(RecordingIoError::ClockReversed))
    ));
    assert_eq!(read.returned_windows(), 1);
    assert!(matches!(
        read.step(6, &NeverCancel)?,
        P::Window { ordinal: 1, .. }
    ));
    assert!(matches!(
        read.step(10, &NeverCancel),
        Err(E::Storage(RecordingIoError::Deadline))
    ));
    assert!(matches!(
        read.step(11, &NeverCancel),
        Err(E::Storage(RecordingIoError::Stopped))
    ));
    // The earlier owned recording stays available even though no aggregate receipt exists.
    let P::Window { recording, .. } = first else {
        return Err("first window disappeared".into());
    };
    assert_eq!(recording.summary().samples, 4);
    let mut read = HevcRecordingRangeRead::new(
        &p,
        &c,
        &slot,
        0..200_000,
        CatalogQueryLimits::default(),
        100,
    )?;
    read.step(0, &NeverCancel)?;
    assert!(matches!(
        read.step(1, &Stop),
        Err(E::Storage(RecordingIoError::Cancelled))
    ));
    assert_eq!(read.returned_windows(), 1);
    Ok(())
}

#[test]
fn corrupt_later_window_and_changed_catalog_cannot_complete_a_partial_read() -> TestResult {
    for corrupt_catalog in [false, true] {
        let (path, mut p, c) = setup(if corrupt_catalog {
            "corrupt_catalog"
        } else {
            "corrupt_media"
        })?;
        publish(&mut p, &c)?;
        let slot = catalog_slot()?;
        let mut read = HevcRecordingRangeRead::new(
            &p,
            &c,
            &slot,
            0..200_000,
            CatalogQueryLimits::default(),
            100,
        )?;
        assert!(matches!(read.step(0, &NeverCancel)?, P::Window { .. }));
        if corrupt_catalog {
            assert!(matches!(read.step(1, &NeverCancel)?, P::Window { .. }));
            damage(
                &path,
                c.manifest()
                    .metadata_digest()
                    .ok_or("missing catalog index")?,
            )?;
        } else {
            let w = window(100_000)?;
            damage(&path, ContentDigest::sha256(w.objects().media))?;
        }
        assert!(read.step(2, &NeverCancel).is_err());
        assert_eq!(read.returned_windows(), if corrupt_catalog { 2 } else { 1 });
        assert!(matches!(
            read.step(3, &NeverCancel),
            Err(E::Storage(RecordingIoError::Stopped))
        ));
    }
    Ok(())
}

#[test]
fn scope_root_codec_and_atomic_output_bounds_remain_separate() -> TestResult {
    let (_, mut p, c) = setup("isolation")?;
    publish(&mut p, &c)?;
    let slot = catalog_slot()?;
    assert!(matches!(
        load_hevc_catalog(
            &p,
            &slot,
            ContentDigest::sha256(b"wrong-root"),
            &scope()?,
            &NeverCancel
        ),
        Err(E::Storage(RecordingIoError::RootConflict))
    ));
    let mut wrong = scope()?;
    wrong.decode_clock = ContentDigest::sha256(b"wrong-clock");
    assert!(matches!(
        load_hevc_catalog(&p, &slot, c.manifest().root(), &wrong, &NeverCancel),
        Err(E::Catalog(CatalogError::Scope))
    ));
    assert!(load_catalog(&p, &slot, c.manifest().root(), &scope()?, &NeverCancel).is_err());
    let limits = CatalogQueryLimits {
        max_windows: 1,
        ..CatalogQueryLimits::default()
    };
    assert!(matches!(
        HevcRecordingRangeRead::new(&p, &c, &slot, 0..200_000, limits, 100),
        Err(E::Catalog(CatalogError::Limit))
    ));
    let mut empty = HevcRecordingRangeRead::new(
        &p,
        &c,
        &slot,
        73_000..100_000,
        CatalogQueryLimits::default(),
        100,
    )?;
    let P::Complete(receipt) = empty.step(0, &NeverCancel)? else {
        return Err("empty range not complete".into());
    };
    assert_eq!(receipt.windows, 0);
    assert_eq!(receipt.output_bytes, 0);
    assert_eq!(receipt.unindexed, vec![73_000..100_000]);
    Ok(())
}

#[test]
fn rehashed_underpriced_descriptor_is_rejected_before_any_excess_output() -> TestResult {
    let (_, mut p, _) = setup("forged_size")?;
    let w = window(1_000)?;
    let s = slot(0)?;
    let basis = scope()?;
    let bytes = index_with_bytes(
        "fss.hevc_recording_catalog.v1",
        &basis,
        &[(&s, w.publication_plan())],
        None,
        Some(1),
    )?;
    let manifest = manifest(HEVC_CATALOG_KIND, &bytes, &[w.publication_plan()], None)?;
    let forged = verify_hevc_catalog(&manifest, &bytes, &basis)?;
    p.stage_object(&bytes)?;
    p.publish(&catalog_slot()?, &manifest)?;
    let loaded = load_hevc_catalog(
        &p,
        &catalog_slot()?,
        forged.manifest().root(),
        &basis,
        &NeverCancel,
    )?;
    let mut read = HevcRecordingRangeRead::new(
        &p,
        &loaded,
        &catalog_slot()?,
        1_001..1_002,
        CatalogQueryLimits {
            max_windows: 1,
            max_output_bytes: 1,
        },
        100,
    )?;
    assert_eq!(read.selection().output_bytes(), 1);
    assert!(matches!(
        read.step(0, &NeverCancel),
        Err(E::Catalog(CatalogError::WindowMismatch))
    ));
    assert_eq!(read.returned_windows(), 0);
    Ok(())
}

#[test]
fn hevc_publication_replays_media_instead_of_trusting_a_hevc_labeled_avc_root() -> TestResult {
    let avc = recording_support::fixture(1, false)?.prepare()?;
    let mut p = LocalRootPublisher::open(fresh("forged_codec")?, limits())?;
    for (_, _, bytes) in avc.children() {
        p.stage_object(bytes)?;
    }
    let objects = avc.children().map(|(_, d, _)| d);
    let fake_window = ObjectManifest::new(
        HEVC_RECORDING_KIND,
        objects[..3].iter().copied(),
        Some(objects[3]),
    )?;
    let s = slot(0)?;
    p.publish(&s, &fake_window)?;
    let basis = CatalogScope {
        recording: avc.summary().scope.clone(),
        ..scope()?
    };
    let roots = [fake_window.root()];
    let index = index(
        "fss.hevc_recording_catalog.v1",
        &basis,
        &[(&s, &avc)],
        Some(&roots),
    )?;
    let root = manifest(HEVC_CATALOG_KIND, &index, &[&avc], Some(&roots))?;
    let catalog = verify_hevc_catalog(&root, &index, &basis)?;
    {
        let mut job = HevcCatalogPublication::new(
            &catalog,
            &mut p,
            catalog_slot()?,
            catalog.byte_len(),
            100,
        )?;
        assert!(job.step(0, &NeverCancel).is_err());
        assert!(matches!(
            job.step(1, &NeverCancel),
            Err(E::Storage(RecordingIoError::Stopped))
        ));
    }
    assert!(p.root(&catalog_slot()?).is_none());
    Ok(())
}

#[test]
fn existing_avc_storage_entrypoints_keep_their_typed_outputs() -> TestResult {
    let mut p = LocalRootPublisher::open(fresh("avc_compatibility")?, limits())?;
    let avc = recording_support::fixture(1, false)?.prepare()?;
    let s = slot(0)?;
    publish_window(&mut p, &s, &avc)?;
    let basis = CatalogScope {
        recording: avc.summary().scope.clone(),
        ..scope()?
    };
    let mut builder = CatalogBuilder::new(basis.clone())?;
    builder.push(&s, &avc)?;
    let c = builder.prepare()?;
    let slot = catalog_slot()?;
    {
        let mut job = CatalogPublication::new(&c, &mut p, slot.clone(), c.byte_len(), 100)?;
        job.step(0, &NeverCancel)?;
        job.step(1, &NeverCancel)?;
        assert!(matches!(
            job.step(2, &NeverCancel)?,
            CatalogProgress::Published(_)
        ));
    }
    let loaded = load_catalog(&p, &slot, c.manifest().root(), &basis, &NeverCancel)?;
    assert!(load_hevc_catalog(&p, &slot, c.manifest().root(), &basis, &NeverCancel).is_err());
    let mut read =
        RecordingRangeRead::new(&p, &loaded, &slot, 0..1, CatalogQueryLimits::default(), 100)?;
    let RangeProgress::Window { recording, .. } = read.step(0, &NeverCancel)? else {
        return Err("missing AVC output".into());
    };
    assert_eq!(recording.objects().media, avc.objects().media);
    assert!(matches!(
        read.step(1, &NeverCancel)?,
        RangeProgress::Complete(_)
    ));
    Ok(())
}

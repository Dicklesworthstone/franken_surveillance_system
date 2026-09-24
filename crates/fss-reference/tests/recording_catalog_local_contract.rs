#![forbid(unsafe_code)]
//! Local catalog publication, reopen and whole-window retrieval with explicit gaps and cancellation.

mod collector_support;
use collector_support::*;
use fss_core::{CanonicalDecoder, ContentDigest};
use fss_object::{ObjectManifest, SpoolLimits};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel, PublishCancellation,
    PublishCutPoint, PublishOutcome, SlotName};
use fss_reference::rtsp::recording::{PreparedRecording, MAX_RECORDING_BYTES};
use fss_reference::rtsp::recording::local::{RecordingIoError, RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording_collector::CollectorLimits;
use fss_reference::rtsp::recording_catalog::*;
use fss_reference::rtsp::recording_catalog::local::*;

fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(16, 512, 16, 128, SpoolLimits::new(128, 32 * 1024 * 1024, 1024 * 1024, 256))
}
fn path(name: &str) -> Result<std::path::PathBuf, Error> {
    let p = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("recording_catalog_contract").join(name);
    match std::fs::remove_dir_all(&p) {
        Ok(()) => {}, Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}, Err(e) => return Err(e.into()),
    }
    Ok(p)
}
fn catalog_scope() -> Result<CatalogScope, Error> {
    Ok(CatalogScope { recording: scope()?, decode_clock: ContentDigest::try_sha256(b"explicit-dts-epoch")?, time_scale: 90_000 })
}
fn window(seq: u64, dts: u64) -> Result<PreparedRecording, Error> {
    let mut c = collector(CollectorLimits::default())?;
    let a = sample(seq, 90_000 + seq as u32 * 3600, true, seq == 3)?;
    a.source(&mut c, 1)?; accepted(c.push_picture(a.timed(dts), 1))?;
    c.seal(2)?; c.take_ready().ok_or_else(|| "missing window".into())
}
fn publish_window(p: &mut LocalRootPublisher, slot: &SlotName, w: &PreparedRecording) -> TestResult {
    let mut job = RecordingPublication::new(w, p, slot.clone(), w.byte_len(), 100)?;
    for i in 0..4 { assert!(matches!(job.step(i, &NeverCancel)?, RecordingProgress::ChildStaged { .. })); }
    assert!(matches!(job.step(4, &NeverCancel)?, RecordingProgress::Published(_)));
    Ok(())
}
fn setup(name: &str) -> Result<(std::path::PathBuf, LocalRootPublisher, RecordingCatalog), Error> {
    let root = path(name)?; let mut p = LocalRootPublisher::open(&root, limits())?;
    let a = window(1, 3600)?; let b = window(3, 10800)?;
    let x = SlotName::parse("first")?; let y = SlotName::parse("second")?;
    publish_window(&mut p, &x, &a)?; publish_window(&mut p, &y, &b)?;
    let c = prepare_catalog(catalog_scope()?, &[CatalogWindow { slot: &x, recording: &a }, CatalogWindow { slot: &y, recording: &b }])?;
    Ok((root, p, c))
}
fn publish(p: &mut LocalRootPublisher, c: &RecordingCatalog) -> TestResult {
    let mut job = CatalogPublication::new(c, p, SlotName::parse("catalog")?, c.byte_len(), 100)?;
    for i in 0..2 { assert!(matches!(job.step(i, &NeverCancel)?, CatalogProgress::WindowVerified { ordinal, .. } if ordinal == i as usize)); }
    assert!(matches!(job.step(2, &NeverCancel)?, CatalogProgress::IndexStaged { .. }));
    assert!(matches!(job.step(3, &NeverCancel)?, CatalogProgress::Published(_)));
    assert!(matches!(job.step(4, &NeverCancel)?, CatalogProgress::Complete));
    Ok(())
}
struct Stop;
impl PublishCancellation for Stop { fn cancel_requested(&self, _: PublishCutPoint) -> bool { true } }

#[test]
fn publish_reopen_and_retrieve_two_whole_windows_with_explicit_gaps() -> TestResult {
    let (root, mut p, c) = setup("reopen")?; publish(&mut p, &c)?; drop(p);
    let p = LocalRootPublisher::open(&root, limits())?; let slot = SlotName::parse("catalog")?;
    let loaded = load_catalog(&p, &slot, c.manifest().root(), &catalog_scope()?, &NeverCancel)?;
    let mut read = RecordingRangeRead::new(&p, &loaded, &slot, 5000..12000, CatalogQueryLimits::default(), 100)?;
    for (now, ordinal, overlap) in [(0, 0, 5000..7200), (1, 1, 10800..12000)] {
        match read.step(now, &NeverCancel)? {
            RangeProgress::Window { ordinal: got, requested_interval, recording } => {
                assert_eq!(got, ordinal); assert_eq!(requested_interval, overlap);
                assert_eq!(recording.manifest().root(), c.entries()[ordinal].root());
                assert_eq!(recording.summary().decode_interval, c.entries()[ordinal].decode_interval());
            }
            other => return Err(format!("unexpected {other:?}").into()),
        }
    }
    match read.step(2, &NeverCancel)? {
        RangeProgress::Complete(r) => {
            assert_eq!(r.windows, 2); assert_eq!(r.unindexed, vec![7200..10800]);
            assert_eq!(r.output_bytes, read.selection().output_bytes());
            assert_eq!(read.selection().unindexed(), std::slice::from_ref(&(7200..10800)));
        }
        other => return Err(format!("unexpected {other:?}").into()),
    }
    assert!(matches!(read.step(3, &NeverCancel)?, RangeProgress::Exhausted));
    Ok(())
}
#[test]
fn unarchived_window_cannot_publish_a_discovery_root() -> TestResult {
    let root = path("unpublished")?; let mut p = LocalRootPublisher::open(&root, limits())?;
    let w = window(1, 0)?;
    let c = prepare_catalog(catalog_scope()?, &[CatalogWindow { slot: &SlotName::parse("missing")?, recording: &w }])?;
    let slot = SlotName::parse("catalog")?;
    {
        let mut job = CatalogPublication::new(&c, &mut p, slot.clone(), c.byte_len(), 100)?;
        assert!(matches!(job.step(0, &NeverCancel), Err(CatalogIoError::Storage(RecordingIoError::NotDurable))));
        assert!(matches!(job.step(1, &NeverCancel), Err(CatalogIoError::Storage(RecordingIoError::Stopped))));
    }
    assert!(p.root(&slot).is_none());
    Ok(())
}
#[test]
fn cancellation_after_index_stage_leaves_no_catalog_and_retry_is_exact() -> TestResult {
    let (_, mut p, c) = setup("cancel_stage")?;
    let slot = SlotName::parse("catalog")?;
    {
        let mut job = CatalogPublication::new(&c, &mut p, slot.clone(), c.byte_len(), 100)?;
        for i in 0..3 { let _ = job.step(i, &NeverCancel)?; }
        assert!(matches!(job.step(3, &Stop), Err(CatalogIoError::Storage(RecordingIoError::Cancelled))));
    }
    assert!(p.root(&slot).is_none());
    publish(&mut p, &c)?;
    assert_eq!(p.root(&slot).ok_or("root")?.root, c.manifest().root());
    Ok(())
}
#[test]
fn partial_delivery_then_cancel_cannot_return_complete() -> TestResult {
    let (_, mut p, c) = setup("cancel_read")?; publish(&mut p, &c)?;
    let mut read = RecordingRangeRead::new(&p, &c, &SlotName::parse("catalog")?, 0..18000, CatalogQueryLimits::default(), 100)?;
    assert!(matches!(read.step(0, &NeverCancel)?, RangeProgress::Window { .. }));
    assert!(matches!(read.step(1, &Stop), Err(CatalogIoError::Storage(RecordingIoError::Cancelled))));
    assert_eq!(read.returned_windows(), 1);
    assert!(matches!(read.step(2, &NeverCancel), Err(CatalogIoError::Storage(RecordingIoError::Stopped))));
    Ok(())
}
#[test]
fn expired_request_never_yields_more_media_and_reversed_time_can_retry() -> TestResult {
    let (_, mut p, c) = setup("deadline")?; publish(&mut p, &c)?;
    let mut read = RecordingRangeRead::new(&p, &c, &SlotName::parse("catalog")?, 0..18000, CatalogQueryLimits::default(), 10)?;
    assert!(matches!(read.step(5, &NeverCancel)?, RangeProgress::Window { .. }));
    assert!(matches!(read.step(4, &NeverCancel), Err(CatalogIoError::Storage(RecordingIoError::ClockReversed))));
    assert!(matches!(read.step(6, &NeverCancel)?, RangeProgress::Window { .. }));
    assert!(matches!(read.step(10, &NeverCancel), Err(CatalogIoError::Storage(RecordingIoError::Deadline))));
    assert!(matches!(read.step(11, &NeverCancel), Err(CatalogIoError::Storage(RecordingIoError::Stopped))));
    Ok(())
}
#[test]
fn empty_query_result_completes_with_unknown_interval_not_absence() -> TestResult {
    let (_, mut p, c) = setup("no_matches")?; publish(&mut p, &c)?;
    let mut read = RecordingRangeRead::new(&p, &c, &SlotName::parse("catalog")?, 8000..9000, CatalogQueryLimits::default(), 10)?;
    match read.step(0, &NeverCancel)? {
        RangeProgress::Complete(r) => { assert_eq!(r.windows, 0); assert_eq!(r.output_bytes, 0); assert_eq!(r.unindexed, vec![8000..9000]); }
        other => return Err(format!("unexpected {other:?}").into()),
    }
    Ok(())
}
#[test]
fn root_scope_budget_and_publisher_bounds_fail_before_output() -> TestResult {
    let (_, mut p, c) = setup("binding")?; publish(&mut p, &c)?;
    let slot = SlotName::parse("catalog")?;
    assert!(matches!(load_catalog(&p, &slot, ContentDigest::try_sha256(b"wrong")?, &catalog_scope()?, &NeverCancel),
        Err(CatalogIoError::Storage(RecordingIoError::RootConflict))));
    let mut wrong = catalog_scope()?; wrong.decode_clock = ContentDigest::try_sha256(b"other-clock")?;
    assert!(matches!(load_catalog(&p, &slot, c.manifest().root(), &wrong, &NeverCancel), Err(CatalogIoError::Catalog(CatalogError::Scope))));
    assert!(matches!(RecordingRangeRead::new(&p, &c, &slot, 0..18000, CatalogQueryLimits { max_output_bytes: 1, ..CatalogQueryLimits::default() }, 10),
        Err(CatalogIoError::Catalog(CatalogError::Limit))));
    assert!(matches!(CatalogPublication::new(&c, &mut p, SlotName::parse("next")?, c.byte_len() - 1, 10),
        Err(CatalogIoError::Storage(RecordingIoError::Budget))));
    let root = path("overpermissive_spool")?; let mut l = limits(); l.spool.max_object_bytes = MAX_RECORDING_BYTES + 1;
    l.spool.max_total_bytes = 64 * 1024 * 1024;
    let mut other = LocalRootPublisher::open(root, l)?;
    assert!(matches!(CatalogPublication::new(&c, &mut other, slot, c.byte_len(), 10), Err(CatalogIoError::Storage(RecordingIoError::Budget))));
    Ok(())
}

// Alter a descriptor but recompute both index checksum and catalog manifest.
// The window's real immutable root remains unchanged. Structural catalog validity
// must not turn the descriptor into verified original-media metadata.
fn lie_about_window_size(c: &RecordingCatalog) -> Result<RecordingCatalog, Error> {
    let mut bytes = c.index_bytes().to_vec();
    let mut d = CanonicalDecoder::new(&bytes);
    d.text()?; d.u64()?; d.text()?; d.text()?; d.u64()?;
    d.digest()?; d.digest()?; d.digest()?; d.u32()?; d.u64()?;
    d.text()?; d.digest()?;
    for _ in 0..5 { d.u64()?; } // start, end, packet/sample/NAL counts
    let at = d.offset();
    bytes[at..at + 8].copy_from_slice(&1_u64.to_be_bytes());
    let body = bytes.len() - 33;
    let checksum = ContentDigest::try_sha256(&bytes[..body])?;
    bytes[body + 1..].copy_from_slice(&checksum.bytes());
    let old_meta = c.manifest().metadata_digest().ok_or("metadata")?;
    let leaves: Vec<_> = c.manifest().children().iter().copied().filter(|d| *d != old_meta).collect();
    let manifest = ObjectManifest::new(CATALOG_KIND, leaves, Some(ContentDigest::try_sha256(&bytes)?))?;
    Ok(verify_catalog(&manifest, &bytes, c.scope())?)
}
#[test]
fn self_consistent_catalog_lie_is_not_published_or_delivered_as_media() -> TestResult {
    let (_, mut p, c) = setup("descriptor_lie")?;
    let forged = lie_about_window_size(&c)?; let slot = SlotName::parse("catalog")?;
    {
        let mut job = CatalogPublication::new(&forged, &mut p, slot.clone(), forged.byte_len(), 100)?;
        assert!(matches!(job.step(0, &NeverCancel), Err(CatalogIoError::Catalog(CatalogError::WindowMismatch))));
    }
    assert!(p.root(&slot).is_none());
    // Simulate a catalog produced by a foreign writer that bypassed this API.
    p.stage_object(forged.index_bytes())?;
    p.publish_cancellable(&slot, forged.manifest(), &NeverCancel)?;
    let loaded = load_catalog(&p, &slot, forged.manifest().root(), &catalog_scope()?, &NeverCancel)?;
    let mut read = RecordingRangeRead::new(&p, &loaded, &slot, 4000..5000, CatalogQueryLimits::default(), 100)?;
    assert!(matches!(read.step(0, &NeverCancel), Err(CatalogIoError::Catalog(CatalogError::WindowMismatch))));
    assert_eq!(read.returned_windows(), 0);
    Ok(())
}
#[test]
fn every_root_publication_crash_boundary_recovers_without_false_visibility() -> TestResult {
    for (i, cut) in [PublishCutPoint::AfterChildrenVerified, PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite, PublishCutPoint::AfterRootRename].into_iter().enumerate() {
        let (root, mut p, c) = setup(&format!("crash_{i}"))?;
        p.inject_crash_at(cut);
        {
            let mut job = CatalogPublication::new(&c, &mut p, SlotName::parse("catalog")?, c.byte_len(), 100)?;
            for now in 0..3 { let _ = job.step(now, &NeverCancel)?; }
            assert!(job.step(3, &NeverCancel).is_err());
        }
        drop(p);
        let mut reopened = LocalRootPublisher::open(&root, limits())?;
        let slot = SlotName::parse("catalog")?;
        if cut == PublishCutPoint::AfterRootRename {
            assert_eq!(load_catalog(&reopened, &slot, c.manifest().root(), &catalog_scope()?, &NeverCancel)?.manifest().root(), c.manifest().root());
        } else { assert!(reopened.root(&slot).is_none()); }
        // An orphaned pre-commit temporary is retained for explicit cleanup;
        // this new authorized slot does not overwrite or erase that evidence.
        let retry_slot = if cut == PublishCutPoint::AfterRootRename { slot } else { SlotName::parse("recovered")? };
        let mut retry = CatalogPublication::new(&c, &mut reopened, retry_slot, c.byte_len(), 100)?;
        for now in 0..3 { let _ = retry.step(now, &NeverCancel)?; }
        match retry.step(3, &NeverCancel)? {
            CatalogProgress::Published(r) => assert_eq!(r.outcome, if cut == PublishCutPoint::AfterRootRename { PublishOutcome::AlreadyPublished } else { PublishOutcome::Published }),
            other => return Err(format!("unexpected {other:?}").into()),
        }
    }
    Ok(())
}

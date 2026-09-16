#![forbid(unsafe_code)]
mod archive_support;
use archive_support::*;
use fss_core::ContentDigest;
use fss_publication::{LocalRootPublisher, NeverCancel, PublishCancellation, PublishCutPoint};
use fss_reference::rtsp::recording_archive::*;

struct Stop;
impl PublishCancellation for Stop { fn cancel_requested(&self, _: PublishCutPoint) -> bool { true } }

#[test]
fn namespace_pins_every_scope_field_and_has_canonical_bounded_slots() -> TestResult {
    let n = namespace()?;
    assert!(n.window_slot(4095)?.as_str().len() <= 128);
    assert_ne!(n.window_slot(0)?, n.page_slot(0)?);
    assert!(matches!(n.window_slot(MAX_ARCHIVE_WINDOWS), Err(ArchiveError::Limit)));
    for field in 0..7 {
        let mut scope = n.scope().clone();
        match field {
            0 => scope.recording.generation += 1,
            1 => scope.recording.anchor = ContentDigest::try_sha256(b"different-anchor")?,
            2 => scope.recording.receive_clock = ContentDigest::try_sha256(b"different-receive")?,
            3 => scope.decode_clock = ContentDigest::try_sha256(b"different-decode")?,
            4 => scope.time_scale += 1,
            5 => scope.recording.sensor = fss_core::SensorId::parse("different-sensor")?,
            _ => scope.recording.stream = fss_core::StreamId::parse("different-stream")?,
        }
        assert_ne!(n.digest(), ArchiveNamespace::new(scope)?.digest());
    }
    Ok(())
}
#[test]
fn empty_archive_is_entirely_unindexed_not_evidence_of_absence() -> TestResult {
    let (_, p) = owner("empty")?;
    let s = ArchiveSnapshot::load(&p, namespace()?, ArchiveLimits::default(), &NeverCancel)?;
    let mut read = ArchiveRead::new(&p, &s, 0..u64::MAX, ArchiveQueryLimits::default(), 100)?;
    match read.step(0, &NeverCancel)? {
        ArchiveReadProgress::Complete(r) => { assert_eq!(r.windows, 0); assert_eq!(r.unindexed, vec![0..u64::MAX]); }
        other => return Err(format!("unexpected {other:?}").into()),
    }
    Ok(())
}
#[test]
fn restart_discovers_and_verifies_range_across_multiple_catalog_pages() -> TestResult {
    let (path, mut p) = owner("pages")?; let ns = namespace()?;
    let a = window(1, 3600)?; let b = window(3, 10800)?;
    let x = ns.window_slot(0)?; let y = ns.window_slot(1)?;
    publish_window(&mut p, &x, &a)?; publish_window(&mut p, &y, &b)?;
    publish_page(&mut p, &ns, 0, &[(&x, &a)])?; publish_page(&mut p, &ns, 1, &[(&y, &b)])?;
    drop(p);
    let p = LocalRootPublisher::open(path, owner_limits())?;
    let s = ArchiveSnapshot::load(&p, ns, ArchiveLimits::default(), &NeverCancel)?;
    assert_eq!(s.pages().len(), 2); assert_eq!(s.indexed_windows(), 2);
    let mut read = ArchiveRead::new(&p, &s, 0..18000, ArchiveQueryLimits::default(), 100)?;
    for i in 0..2 {
        match read.step(i, &NeverCancel)? {
            ArchiveReadProgress::Window { ordinal, recording, .. } => {
                assert_eq!(ordinal, i as usize); assert_eq!(recording.manifest().root(), s.windows()[ordinal].root());
            }
            other => return Err(format!("unexpected {other:?}").into()),
        }
    }
    match read.step(2, &NeverCancel)? {
        ArchiveReadProgress::Complete(r) => {
            assert_eq!(r.windows, 2); assert_eq!(r.output_bytes, (a.byte_len() + b.byte_len()) as u64);
            assert_eq!(r.unindexed, vec![0..3600, 7200..10800, 14400..18000]);
        }
        other => return Err(format!("unexpected {other:?}").into()),
    }
    assert!(matches!(read.step(3, &NeverCancel)?, ArchiveReadProgress::Exhausted));
    Ok(())
}
#[test]
fn durable_unindexed_tail_is_recovered_without_pretending_it_has_a_catalog() -> TestResult {
    let (_, mut p) = owner("tail")?; let ns = namespace()?; let a = window(1, 3600)?;
    publish_window(&mut p, &ns.window_slot(0)?, &a)?;
    let s = ArchiveSnapshot::load(&p, ns, ArchiveLimits::default(), &NeverCancel)?;
    assert_eq!(s.windows().len(), 1); assert_eq!(s.indexed_windows(), 0);
    assert_eq!(s.unindexed_windows()[0].root(), a.manifest().root());
    let selected = s.select(3600..7200, ArchiveQueryLimits::default())?;
    assert!(selected.ordinals().is_empty()); assert_eq!(selected.unindexed(), &[3600..7200]);
    Ok(())
}
#[test]
fn a_missing_ordinal_or_page_prefix_is_not_silently_skipped() -> TestResult {
    let (_, mut p) = owner("hole")?; let ns = namespace()?; let a = window(1, 3600)?;
    publish_window(&mut p, &ns.window_slot(1)?, &a)?;
    assert!(matches!(ArchiveSnapshot::load(&p, ns, ArchiveLimits::default(), &NeverCancel), Err(ArchiveError::Sequence)));
    Ok(())
}
#[test]
fn discovery_and_output_budgets_refuse_before_returning_partial_success() -> TestResult {
    let (_, mut p) = owner("limits")?; let ns = namespace()?; let a = window(1, 3600)?;
    let x = ns.window_slot(0)?;
    publish_window(&mut p, &x, &a)?; publish_page(&mut p, &ns, 0, &[(&x, &a)])?;
    assert!(matches!(ArchiveSnapshot::load(&p, ns.clone(), ArchiveLimits { max_scan_roots: 1, ..ArchiveLimits::default() }, &NeverCancel), Err(ArchiveError::Limit)));
    assert!(ArchiveSnapshot::load(&p, ns.clone(), ArchiveLimits::default(), &Stop).is_err());
    let s = ArchiveSnapshot::load(&p, ns, ArchiveLimits::default(), &NeverCancel)?;
    assert!(matches!(s.select(0..10000, ArchiveQueryLimits { max_output_bytes: a.byte_len() as u64 - 1, ..ArchiveQueryLimits::default() }), Err(ArchiveError::Limit)));
    assert!(s.select(7200..8000, ArchiveQueryLimits::default())?.ordinals().is_empty());
    Ok(())
}
#[test]
fn cancellation_after_one_window_does_not_yield_an_aggregate_receipt() -> TestResult {
    let (_, mut p) = owner("partial")?; let ns = namespace()?; let a = window(1, 3600)?;
    let x = ns.window_slot(0)?;
    publish_window(&mut p, &x, &a)?; publish_page(&mut p, &ns, 0, &[(&x, &a)])?;
    let s = ArchiveSnapshot::load(&p, ns, ArchiveLimits::default(), &NeverCancel)?;
    let mut read = ArchiveRead::new(&p, &s, 0..10000, ArchiveQueryLimits::default(), 100)?;
    assert!(matches!(read.step(0, &NeverCancel)?, ArchiveReadProgress::Window { .. }));
    assert!(matches!(read.step(1, &Stop), Err(ArchiveError::Cancelled)));
    assert_eq!(read.returned_windows(), 1);
    assert!(matches!(read.step(2, &NeverCancel), Err(ArchiveError::Blocked)));
    Ok(())
}

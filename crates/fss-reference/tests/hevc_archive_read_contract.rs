#![forbid(unsafe_code)]
//! Actual source replay, durable catalogs, cross-page retrieval and recovery faults.

mod hevc_archive_support;
mod hevc_catalog_support;
mod hevc_recording_support;
use fss_core::{CanonicalEncoder, ContentDigest};
use fss_publication::{LocalRootPublisher, NeverCancel, SlotName};
use fss_reference::rtsp::recording_archive::hevc::*;
use fss_reference::rtsp::recording_archive::*;
use fss_reference::rtsp::recording_catalog::CatalogError;
use hevc_archive_support::*;
use hevc_catalog_support as fixture;

#[test]
fn namespace_and_empty_inventory_are_codec_separated_and_avc_bytes_stay_frozen() -> TestResult {
    let scope = fixture::scope()?;
    let avc = ArchiveNamespace::new(scope.clone())?;
    let hevc = HevcArchiveNamespace::new(scope.clone())?;
    assert_ne!(avc.digest(), hevc.digest());
    for (domain, prefix, expected_digest, expected_slot) in [
        (
            "fss.local_recording_archive_namespace.v1",
            "fssa1",
            avc.digest(),
            avc.window_slot(0)?,
        ),
        (
            "fss.local_hevc_recording_archive_namespace.v1",
            "fssh1",
            hevc.digest(),
            hevc.window_slot(0)?,
        ),
    ] {
        let mut e = CanonicalEncoder::new();
        e.text(domain);
        e.text(scope.recording.sensor.as_str());
        e.text(scope.recording.stream.as_str());
        e.u64(scope.recording.generation);
        e.digest(scope.recording.anchor);
        e.digest(scope.recording.receive_clock);
        e.digest(scope.decode_clock);
        e.u32(scope.time_scale);
        let digest = ContentDigest::try_sha256(&e.finish_checked()?)?;
        assert_eq!(digest, expected_digest);
        let text = digest.to_text();
        assert_eq!(
            expected_slot.as_str(),
            format!(
                "{prefix}-{}-w-0000000000000000",
                text.strip_prefix("sha256:").ok_or("hash")?
            )
        );
    }
    let p = LocalRootPublisher::open(fresh("empty_namespace")?, limits())?;
    let a = ArchiveSnapshot::load(&p, avc, archive_limits(), &NeverCancel)?;
    let h = HevcArchiveSnapshot::load(&p, hevc, archive_limits(), &NeverCancel)?;
    assert_ne!(a.digest()?, h.digest()?);
    let mut e = CanonicalEncoder::new();
    e.text("fss.local_recording_archive_snapshot.v1");
    e.digest(a.namespace().digest());
    e.u64(0);
    e.u64(0);
    e.u64(0);
    assert_eq!(
        a.digest()?,
        ContentDigest::try_sha256(&e.finish_checked()?)?
    );
    assert!(matches!(
        HevcArchiveSnapshot::load(&p, namespace()?, archive_limits(), &Stop),
        Err(ArchiveError::Cancelled)
    ));
    assert!(namespace()?.window_slot(MAX_ARCHIVE_WINDOWS).is_err());
    Ok(())
}

#[test]
fn reopen_reads_three_pages_as_typed_whole_hevc_windows_and_explicit_decode_gaps() -> TestResult {
    let (root, p, ns, windows) = seed("cross_pages", 3)?;
    let before = HevcArchiveSnapshot::load(&p, ns.clone(), archive_limits(), &NeverCancel)?;
    let digest = before.digest()?;
    drop(before);
    drop(p);
    let p = LocalRootPublisher::open(&root, limits())?;
    let snapshot = HevcArchiveSnapshot::load(&p, ns, archive_limits(), &NeverCancel)?;
    assert_eq!(snapshot.digest()?, digest);
    assert_eq!(snapshot.pages().len(), 3);
    assert!(snapshot.unindexed_windows().is_empty());
    let mut read = HevcArchiveRead::new(
        &p,
        &snapshot,
        100..300_000,
        ArchiveQueryLimits::default(),
        100,
    )?;
    assert_eq!(read.selection().ordinals(), &[0, 1, 2]);
    let gaps = vec![72_000..90_000, 162_000..180_000, 252_000..300_000];
    assert_eq!(read.selection().unindexed(), gaps);
    for (i, expected) in windows.iter().enumerate() {
        let HevcArchiveReadProgress::Window {
            ordinal,
            requested_interval,
            recording,
        } = read.step(i as u64, &NeverCancel)?
        else {
            return Err("missing typed HEVC window".into());
        };
        assert_eq!(ordinal, i);
        assert_eq!(
            requested_interval,
            (if i == 0 { 100 } else { i as u64 * 90_000 })..i as u64 * 90_000 + 72_000
        );
        assert_eq!(recording.objects().source, expected.objects().source);
        assert_eq!(recording.objects().media, expected.objects().media);
        assert_eq!(recording.samples(), expected.samples());
        assert_eq!(recording.mappings(), expected.mappings());
        assert_eq!(recording.source_only_nals(), expected.source_only_nals());
    }
    let HevcArchiveReadProgress::Complete(receipt) = read.step(3, &NeverCancel)? else {
        return Err("no completion".into());
    };
    assert_eq!(receipt.windows, 3);
    assert_eq!(receipt.unindexed, gaps);
    assert_eq!(receipt.scope, fixture::scope()?);
    assert_eq!(receipt.snapshot_digest, digest);
    assert_eq!(
        receipt.output_bytes,
        windows.iter().map(|w| w.byte_len() as u64).sum::<u64>()
    );
    assert!(matches!(
        read.step(200, &Stop)?,
        HevcArchiveReadProgress::Exhausted
    ));
    Ok(())
}

#[test]
fn durable_tail_is_not_indexed_and_a_new_page_does_not_rewrite_an_old_snapshot() -> TestResult {
    let (_, mut p, ns, windows) = seed("tail", 2)?;
    let old = HevcArchiveSnapshot::load(&p, ns.clone(), archive_limits(), &NeverCancel)?;
    assert_eq!(old.windows().len(), 3);
    assert_eq!(old.indexed_windows(), 2);
    assert_eq!(
        old.unindexed_windows()[0].root(),
        windows[2].manifest().root()
    );
    assert!(
        old.select(180_000..252_000, ArchiveQueryLimits::default())?
            .ordinals()
            .is_empty()
    );
    let catalog = page(&ns, 2, &windows[2..])?;
    publish_page(&mut p, &ns, 2, &catalog)?;
    let new = HevcArchiveSnapshot::load(&p, ns, archive_limits(), &NeverCancel)?;
    assert_ne!(old.digest()?, new.digest()?);
    assert_eq!(
        new.select(180_000..252_000, ArchiveQueryLimits::default())?
            .ordinals(),
        &[2]
    );
    let mut read = HevcArchiveRead::new(
        &p,
        &old,
        180_000..252_000,
        ArchiveQueryLimits::default(),
        100,
    )?;
    let HevcArchiveReadProgress::Complete(receipt) = read.step(0, &NeverCancel)? else {
        return Err("no empty receipt".into());
    };
    assert_eq!(receipt.windows, 0);
    assert_eq!(receipt.unindexed, vec![180_000..252_000]);
    Ok(())
}

#[test]
fn selection_prices_whole_windows_and_refuses_all_on_any_limit_overflow() -> TestResult {
    let (_, p, ns, windows) = seed("query_limits", 3)?;
    let s = HevcArchiveSnapshot::load(&p, ns, archive_limits(), &NeverCancel)?;
    assert!(matches!(
        s.select(
            1..2,
            ArchiveQueryLimits {
                max_windows: 1,
                max_output_bytes: windows[0].byte_len() as u64 - 1
            }
        ),
        Err(ArchiveError::Limit)
    ));
    assert_eq!(
        s.select(
            1..2,
            ArchiveQueryLimits {
                max_windows: 1,
                max_output_bytes: windows[0].byte_len() as u64
            }
        )?
        .output_bytes(),
        windows[0].byte_len() as u64
    );
    assert!(matches!(
        s.select(
            0..300_000,
            ArchiveQueryLimits {
                max_windows: 2,
                ..ArchiveQueryLimits::default()
            }
        ),
        Err(ArchiveError::Limit)
    ));
    assert!(matches!(
        s.select(5..5, ArchiveQueryLimits::default()),
        Err(ArchiveError::Catalog(CatalogError::Interval))
    ));
    assert!(
        s.select(u64::MAX - 1..u64::MAX, ArchiveQueryLimits::default())?
            .ordinals()
            .is_empty()
    );
    assert_eq!(
        s.select(72_000..90_000, ArchiveQueryLimits::default())?
            .unindexed(),
        std::slice::from_ref(&(72_000..90_000))
    );
    Ok(())
}

#[test]
fn recovery_refuses_holes_overlapping_pages_wrong_bindings_and_same_prefix_garbage() -> TestResult {
    for case in 0..4 {
        let mut p = LocalRootPublisher::open(fresh(&format!("invalid_layout_{case}"))?, limits())?;
        let ns = namespace()?;
        let a = fixture::window(0)?;
        let b = fixture::window(90_000)?;
        if case == 0 {
            publish_window(&mut p, &ns.window_slot(1)?, &a)?;
        } else if case == 3 {
            let malformed = ns.window_slot(0)?.as_str().replace("-w-", "-q-");
            publish_window(&mut p, &SlotName::parse(&malformed)?, &a)?;
        } else {
            publish_window(&mut p, &ns.window_slot(0)?, &a)?;
            publish_window(&mut p, &ns.window_slot(1)?, &b)?;
            if case == 1 {
                let c = page(&ns, 1, &[b])?;
                publish_page(&mut p, &ns, 1, &c)?;
            } else {
                let c = page(&ns, 0, &[a, b])?;
                publish_page(&mut p, &ns, 0, &c)?;
                // Same page bytes in another catalog slot may be durable but overlap ordinal zero.
                p.publish(&ns.page_slot(1)?, c.manifest())?;
            }
        }
        assert!(HevcArchiveSnapshot::load(&p, ns, archive_limits(), &NeverCancel).is_err());
    }
    Ok(())
}

#[test]
fn codec_namespace_relabeling_does_not_select_a_weaker_window_verifier() -> TestResult {
    let (_, mut p, ns, _) = seed("codec_substitution", 1)?;
    let avc = ArchiveNamespace::new(ns.scope().clone())?;
    let original = p.root(&ns.window_slot(0)?).ok_or("missing root")?.root;
    let bytes = p.spool().read(original)?;
    let manifest = fss_object::ObjectManifest::from_canonical_bytes(&bytes)?;
    p.publish(&avc.window_slot(0)?, &manifest)?;
    assert!(ArchiveSnapshot::load(&p, avc, archive_limits(), &NeverCancel).is_err());
    // The foreign AVC namespace cannot poison the correctly pinned HEVC inventory.
    assert_eq!(
        HevcArchiveSnapshot::load(&p, ns, archive_limits(), &NeverCancel)?
            .windows()
            .len(),
        3
    );
    Ok(())
}

#[test]
fn corrupted_source_or_false_catalog_descriptor_prevents_recovery() -> TestResult {
    let (root, p, ns, windows) = seed("corrupt_source", 3)?;
    corrupt(&root, windows[0].publication_plan().children()[0].1)?;
    assert!(HevcArchiveSnapshot::load(&p, ns, archive_limits(), &NeverCancel).is_err());
    let (_, mut p, ns, windows) = seed("false_descriptor", 0)?;
    let slot = ns.window_slot(0)?;
    let index = fixture::index_with_bytes(
        "fss.hevc_recording_catalog.v1",
        ns.scope(),
        &[(&slot, windows[0].publication_plan())],
        None,
        Some(1),
    )?;
    let manifest = fixture::manifest(
        "hevc_recording_catalog_v1",
        &index,
        &[windows[0].publication_plan()],
        None,
    )?;
    p.stage_object(&index)?;
    p.publish(&ns.page_slot(0)?, &manifest)?;
    // Consistent hashes do not validate a lying size descriptor against source replay.
    assert!(matches!(
        HevcArchiveSnapshot::load(&p, ns, archive_limits(), &NeverCancel),
        Err(ArchiveError::Metadata)
    ));
    Ok(())
}

#[test]
fn later_corruption_preserves_earlier_owned_output_but_blocks_aggregate_success() -> TestResult {
    let (root, p, ns, windows) = seed("later_corrupt", 3)?;
    let snapshot = HevcArchiveSnapshot::load(&p, ns, archive_limits(), &NeverCancel)?;
    let mut read = HevcArchiveRead::new(
        &p,
        &snapshot,
        0..300_000,
        ArchiveQueryLimits::default(),
        100,
    )?;
    let HevcArchiveReadProgress::Window { recording, .. } = read.step(0, &NeverCancel)? else {
        return Err("first window".into());
    };
    corrupt(&root, windows[1].publication_plan().children()[2].1)?;
    assert!(read.step(1, &NeverCancel).is_err());
    assert_eq!(read.returned_windows(), 1);
    assert!(matches!(
        read.step(2, &NeverCancel),
        Err(ArchiveError::Blocked)
    ));
    assert_eq!(recording.objects().media, windows[0].objects().media);
    Ok(())
}

#[test]
fn cancellation_at_every_read_probe_prevents_window_disclosure_and_stops_attempt() -> TestResult {
    let (_, p, ns, _) = seed("cancellation", 3)?;
    let snapshot = HevcArchiveSnapshot::load(&p, ns, archive_limits(), &NeverCancel)?;
    let count = Probe {
        calls: std::cell::Cell::new(0),
        stop_at: usize::MAX,
    };
    let mut baseline =
        HevcArchiveRead::new(&p, &snapshot, 1..2, ArchiveQueryLimits::default(), 100)?;
    assert!(matches!(
        baseline.step(0, &count)?,
        HevcArchiveReadProgress::Window { .. }
    ));
    assert!(count.calls.get() > 1);
    for stop_at in 1..=count.calls.get() {
        let cancel = Probe {
            calls: std::cell::Cell::new(0),
            stop_at,
        };
        let mut read =
            HevcArchiveRead::new(&p, &snapshot, 1..2, ArchiveQueryLimits::default(), 100)?;
        assert!(read.step(0, &cancel).is_err(), "probe {stop_at}");
        assert_eq!(read.returned_windows(), 0);
        assert!(matches!(
            read.step(1, &NeverCancel),
            Err(ArchiveError::Blocked)
        ));
    }
    Ok(())
}

#[test]
fn deadline_and_partial_cancellation_never_complete_but_clock_reversal_is_retryable() -> TestResult
{
    let (_, p, ns, _) = seed("read_clock", 3)?;
    let snapshot = HevcArchiveSnapshot::load(&p, ns, archive_limits(), &NeverCancel)?;
    let mut read =
        HevcArchiveRead::new(&p, &snapshot, 0..300_000, ArchiveQueryLimits::default(), 10)?;
    assert!(matches!(
        read.step(5, &NeverCancel)?,
        HevcArchiveReadProgress::Window { ordinal: 0, .. }
    ));
    assert!(matches!(
        read.step(4, &NeverCancel),
        Err(ArchiveError::ClockReversed)
    ));
    assert!(matches!(
        read.step(6, &NeverCancel)?,
        HevcArchiveReadProgress::Window { ordinal: 1, .. }
    ));
    assert!(matches!(
        read.step(10, &NeverCancel),
        Err(ArchiveError::Deadline)
    ));
    assert_eq!(read.returned_windows(), 2);
    assert!(matches!(
        read.step(11, &NeverCancel),
        Err(ArchiveError::Blocked)
    ));
    let mut cancelled = HevcArchiveRead::new(
        &p,
        &snapshot,
        0..300_000,
        ArchiveQueryLimits::default(),
        100,
    )?;
    cancelled.step(0, &NeverCancel)?;
    assert!(matches!(
        cancelled.step(1, &Stop),
        Err(ArchiveError::Cancelled)
    ));
    assert_eq!(cancelled.returned_windows(), 1);
    Ok(())
}

#[test]
fn empty_answers_and_completion_recheck_all_pages_in_the_selected_inventory() -> TestResult {
    let (root, p, ns, _) = seed("empty_revalidation", 3)?;
    let snapshot = HevcArchiveSnapshot::load(&p, ns, archive_limits(), &NeverCancel)?;
    let mut read = HevcArchiveRead::new(
        &p,
        &snapshot,
        500_000..600_000,
        ArchiveQueryLimits::default(),
        100,
    )?;
    corrupt(
        &root,
        snapshot.pages()[2]
            .catalog()
            .manifest()
            .metadata_digest()
            .ok_or("metadata")?,
    )?;
    assert!(read.step(0, &NeverCancel).is_err());
    assert!(matches!(
        read.step(1, &NeverCancel),
        Err(ArchiveError::Blocked)
    ));
    Ok(())
}

#[test]
fn recovery_limits_and_foreign_owner_cannot_produce_false_success() -> TestResult {
    let (_, p, ns, _) = seed("recovery_limits", 3)?;
    for limits in [
        ArchiveLimits {
            max_windows: 2,
            ..archive_limits()
        },
        ArchiveLimits {
            max_pages: 2,
            ..archive_limits()
        },
        ArchiveLimits {
            max_scan_roots: 1,
            ..archive_limits()
        },
    ] {
        assert!(matches!(
            HevcArchiveSnapshot::load(&p, ns.clone(), limits, &NeverCancel),
            Err(ArchiveError::Limit)
        ));
    }
    let snapshot = HevcArchiveSnapshot::load(&p, ns, archive_limits(), &NeverCancel)?;
    let foreign = LocalRootPublisher::open(fresh("foreign_owner")?, limits())?;
    let mut read = HevcArchiveRead::new(
        &foreign,
        &snapshot,
        1..2,
        ArchiveQueryLimits::default(),
        100,
    )?;
    assert!(read.step(0, &NeverCancel).is_err());
    assert_eq!(read.returned_windows(), 0);
    // A request for an unindexed interval still cannot skip missing page roots.
    let mut empty = HevcArchiveRead::new(
        &foreign,
        &snapshot,
        500_000..600_000,
        ArchiveQueryLimits::default(),
        100,
    )?;
    assert!(empty.step(0, &NeverCancel).is_err());
    Ok(())
}

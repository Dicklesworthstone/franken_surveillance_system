#![forbid(unsafe_code)]
//! Actual HEVC window publication, automatic pages, interrupted writes and recovery.

mod hevc_archive_support;
mod hevc_catalog_support;
mod hevc_recording_support;
mod recording_support;
use fss_core::ContentDigest;
use fss_publication::{
    LocalPublicationState, LocalRootPublisher, NeverCancel, PublishCutPoint, PublishOutcome,
};
use fss_reference::rtsp::recording::hevc::PreparedHevcRecording;
use fss_reference::rtsp::recording::local::RecordingIoError;
use fss_reference::rtsp::recording_archive::hevc::*;
use fss_reference::rtsp::recording_archive::*;
use fss_reference::rtsp::recording_catalog::CatalogScope;
use hevc_archive_support::*;
use hevc_catalog_support as fixture;

fn offer(
    writer: &mut HevcRecordingArchiveWriter<'_>,
    base: u64,
    now: u64,
) -> Result<ArchiveAdmission, Error> {
    let recording = fixture::window(base)?;
    let reservation = recording.byte_len();
    Ok(writer.offer(recording, reservation, now)?)
}
fn drain(
    writer: &mut HevcRecordingArchiveWriter<'_>,
    now: u64,
) -> Result<Vec<ArchiveWriteProgress>, Error> {
    let mut output = Vec::new();
    for _ in 0..128 {
        let event = writer.step(now, &NeverCancel)?;
        let stopped = matches!(
            event,
            ArchiveWriteProgress::Ready { .. }
                | ArchiveWriteProgress::Finished { .. }
                | ArchiveWriteProgress::Exhausted
        );
        output.push(event);
        if stopped {
            return Ok(output);
        }
    }
    Err("archive failed to reach a bounded wait or terminal state".into())
}
fn cut_points() -> [PublishCutPoint; 4] {
    [
        PublishCutPoint::AfterChildrenVerified,
        PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite,
        PublishCutPoint::AfterRootRename,
    ]
}
fn one_unindexed(
    name: &str,
) -> Result<
    (
        std::path::PathBuf,
        LocalRootPublisher,
        HevcArchiveNamespace,
        PreparedHevcRecording,
    ),
    Error,
> {
    let root = fresh(name)?;
    let mut p = LocalRootPublisher::open(&root, limits())?;
    let ns = namespace()?;
    let w = fixture::window(0)?;
    publish_window(&mut p, &ns.window_slot(0)?, &w)?;
    Ok((root, p, ns, w))
}

#[test]
fn automatic_two_window_pages_and_final_partial_page_reopen_as_one_hevc_archive() -> TestResult {
    let root = fresh("writer_rotation")?;
    let mut p = LocalRootPublisher::open(&root, limits())?;
    let ns = namespace()?;
    let expected: Vec<_> = [0, 90_000, 180_000]
        .into_iter()
        .map(fixture::window)
        .collect::<Result<_, _>>()?;
    let final_digest;
    {
        let mut writer = HevcRecordingArchiveWriter::open(
            &mut p,
            ns.clone(),
            archive_limits(),
            0,
            100,
            &NeverCancel,
        )?;
        for (ordinal, base) in [0, 90_000, 180_000].into_iter().enumerate() {
            let admission = offer(&mut writer, base, ordinal as u64)?;
            assert_eq!(admission.ordinal, ordinal);
            assert_eq!(admission.slot, ns.window_slot(ordinal)?);
            assert_eq!(admission.root, expected[ordinal].manifest().root());
            assert_eq!(writer.snapshot().windows().len(), ordinal); // offer is not publication.
            let events = drain(&mut writer, ordinal as u64)?;
            assert!(
                matches!(&events[0], ArchiveWriteProgress::WindowDurable { ordinal: got, receipt }
                if *got == ordinal && receipt.claims.local == LocalPublicationState::Durable)
            );
            if ordinal == 1 {
                assert!(events.iter().any(|e| matches!(
                    e,
                    ArchiveWriteProgress::CatalogPublished {
                        first_ordinal: 0,
                        windows: 2,
                        ..
                    }
                )));
            }
        }
        assert_eq!(writer.snapshot().indexed_windows(), 2);
        assert_eq!(writer.snapshot().unindexed_windows().len(), 1);
        writer.finish();
        let events = drain(&mut writer, 3)?;
        assert!(events.iter().any(|e| matches!(
            e,
            ArchiveWriteProgress::CatalogPublished {
                first_ordinal: 2,
                windows: 1,
                ..
            }
        )));
        let Some(ArchiveWriteProgress::Finished {
            snapshot_digest,
            windows: 3,
            pages: 2,
        }) = events.last()
        else {
            return Err("missing complete archive receipt".into());
        };
        final_digest = *snapshot_digest;
        assert!(matches!(
            writer.step(200, &Stop)?,
            ArchiveWriteProgress::Exhausted
        ));
        assert!(matches!(writer.retry(4, 100), Err(ArchiveError::Closed)));
        let retired = writer.retire();
        assert!(retired.pending.is_none());
        assert!(retired.prepared_page.is_none());
        assert_eq!(retired.snapshot.digest()?, final_digest);
    }
    drop(p);
    let p = LocalRootPublisher::open(&root, limits())?;
    let recovered = HevcArchiveSnapshot::load(&p, ns, archive_limits(), &NeverCancel)?;
    assert_eq!(recovered.digest()?, final_digest);
    assert_eq!(recovered.pages()[0].catalog().entries().len(), 2);
    assert_eq!(recovered.pages()[1].first_ordinal(), 2);
    let mut read = HevcArchiveRead::new(
        &p,
        &recovered,
        0..300_000,
        ArchiveQueryLimits::default(),
        100,
    )?;
    for (ordinal, w) in expected.iter().enumerate() {
        let HevcArchiveReadProgress::Window {
            ordinal: got,
            recording,
            ..
        } = read.step(ordinal as u64, &NeverCancel)?
        else {
            return Err("typed readback missing".into());
        };
        assert_eq!(got, ordinal);
        assert_eq!(recording.objects().source, w.objects().source);
        assert_eq!(recording.objects().media, w.objects().media);
        assert_eq!(recording.mappings(), w.mappings());
    }
    assert!(matches!(
        read.step(3, &NeverCancel)?,
        HevcArchiveReadProgress::Complete(_)
    ));
    Ok(())
}

#[test]
fn recovered_small_tail_flushes_before_new_admission_then_resumes_exact_next_ordinal() -> TestResult
{
    let (root, p, ns, _) = one_unindexed("writer_recovered_tail")?;
    drop(p);
    let mut p = LocalRootPublisher::open(&root, limits())?;
    let mut writer = HevcRecordingArchiveWriter::open(
        &mut p,
        ns.clone(),
        archive_limits(),
        0,
        100,
        &NeverCancel,
    )?;
    let w = fixture::window(90_000)?;
    let bytes = w.byte_len();
    let root = w.manifest().root();
    let refused = writer
        .offer(w, bytes, 1)
        .err()
        .ok_or("unindexed recovery allowed a new window")?;
    assert!(matches!(*refused.reason, ArchiveError::Backpressure));
    assert_eq!(refused.recording.manifest().root(), root);
    let events = drain(&mut writer, 1)?;
    assert!(matches!(
        &events[0],
        ArchiveWriteProgress::PageStarted {
            first_ordinal: 0,
            windows: 1
        }
    ));
    assert!(events.iter().any(|e| matches!(
        e,
        ArchiveWriteProgress::CatalogPublished {
            first_ordinal: 0,
            windows: 1,
            ..
        }
    )));
    let admission = writer.offer(*refused.recording, bytes, 2)?;
    assert_eq!(admission.ordinal, 1);
    assert_eq!(admission.slot, ns.window_slot(1)?);
    assert_eq!(admission.root, root);
    drain(&mut writer, 2)?;
    writer.finish();
    drain(&mut writer, 3)?;
    assert_eq!(writer.snapshot().windows().len(), 2);
    assert_eq!(writer.snapshot().pages().len(), 2);
    Ok(())
}

#[test]
fn reservation_pressure_scope_and_order_refusals_return_exact_unconsumed_recordings() -> TestResult
{
    let mut p = LocalRootPublisher::open(fresh("writer_transactional")?, limits())?;
    let mut writer = HevcRecordingArchiveWriter::open(
        &mut p,
        namespace()?,
        archive_limits(),
        0,
        100,
        &NeverCancel,
    )?;
    let w = fixture::window(90_000)?;
    let bytes = w.byte_len();
    let root = w.manifest().root();
    let failure = writer
        .offer(w, bytes - 1, 1)
        .err()
        .ok_or("under-reservation accepted")?;
    assert!(matches!(*failure.reason, ArchiveError::Limit));
    assert_eq!(failure.recording.manifest().root(), root);
    assert_eq!(writer.snapshot().windows().len(), 0);
    assert_eq!(writer.offer(*failure.recording, bytes, 1)?.ordinal, 0);
    let next = fixture::window(180_000)?;
    let next_size = next.byte_len();
    let next_root = next.manifest().root();
    let failure = writer
        .offer(next, next_size, 2)
        .err()
        .ok_or("second pending window admitted")?;
    assert!(matches!(*failure.reason, ArchiveError::Backpressure));
    assert_eq!(failure.recording.manifest().root(), next_root);
    assert_eq!(
        writer
            .pending()
            .ok_or("pending disappeared")?
            .manifest()
            .root(),
        root
    );
    drain(&mut writer, 2)?;
    let repeated = fixture::window(90_000)?;
    let size = repeated.byte_len();
    assert!(matches!(
        *writer
            .offer(repeated, size, 3)
            .err()
            .ok_or("duplicate accepted")?
            .reason,
        ArchiveError::Duplicate
    ));
    let backwards = fixture::window(0)?;
    let size = backwards.byte_len();
    assert!(matches!(
        *writer
            .offer(backwards, size, 3)
            .err()
            .ok_or("backward window accepted")?
            .reason,
        ArchiveError::Sequence
    ));
    let mut scope = hevc_recording_support::scope()?;
    scope.anchor = ContentDigest::sha256(b"other-owner-anchor");
    let foreign = fss_reference::rtsp::recording::hevc::prepare_hevc_recording(
        scope,
        &hevc_recording_support::configuration()?,
        90_000,
        &hevc_recording_support::timings(4),
        &hevc_recording_support::borrowed(&hevc_recording_support::packets()?),
    )?;
    let size = foreign.byte_len();
    assert!(matches!(
        *writer
            .offer(foreign, size, 3)
            .err()
            .ok_or("foreign scope accepted")?
            .reason,
        ArchiveError::Scope
    ));
    assert_eq!(writer.snapshot().windows().len(), 1);
    assert_eq!(writer.offer(*failure.recording, next_size, 3)?.ordinal, 1);
    drain(&mut writer, 3)?;
    Ok(())
}

#[test]
fn cancellation_at_every_window_publication_probe_retains_pending_and_retries_same_root()
-> TestResult {
    let ns = namespace()?;
    let mut count_p = LocalRootPublisher::open(fresh("writer_probe_baseline")?, limits())?;
    let count = Probe {
        calls: std::cell::Cell::new(0),
        stop_at: usize::MAX,
    };
    {
        let mut writer = HevcRecordingArchiveWriter::open(
            &mut count_p,
            ns.clone(),
            archive_limits(),
            0,
            100,
            &NeverCancel,
        )?;
        offer(&mut writer, 0, 0)?;
        assert!(matches!(
            writer.step(1, &count)?,
            ArchiveWriteProgress::WindowDurable { .. }
        ));
    }
    assert!(count.calls.get() > 1);
    for stop_at in 1..=count.calls.get() {
        let mut p = LocalRootPublisher::open(fresh(&format!("writer_probe_{stop_at}"))?, limits())?;
        let mut writer = HevcRecordingArchiveWriter::open(
            &mut p,
            ns.clone(),
            archive_limits(),
            0,
            100,
            &NeverCancel,
        )?;
        let admission = offer(&mut writer, 0, 0)?;
        let cancelled = Probe {
            calls: std::cell::Cell::new(0),
            stop_at,
        };
        assert!(writer.step(1, &cancelled).is_err(), "probe {stop_at}");
        assert_eq!(writer.snapshot().windows().len(), 0);
        assert_eq!(
            writer.pending().ok_or("lost pending")?.manifest().root(),
            admission.root
        );
        assert!(matches!(
            writer.step(2, &NeverCancel),
            Err(ArchiveError::Blocked)
        ));
        writer.retry(2, 100)?;
        let ArchiveWriteProgress::WindowDurable { ordinal, receipt } =
            writer.step(2, &NeverCancel)?
        else {
            return Err("retry did not publish same original".into());
        };
        assert_eq!(ordinal, 0);
        assert_eq!(receipt.root, admission.root);
        assert_eq!(writer.snapshot().windows()[0].slot(), &admission.slot);
    }
    Ok(())
}

#[test]
fn all_window_root_crash_cuts_preserve_source_ownership_and_lost_ack_recovery() -> TestResult {
    for (ordinal, cut) in cut_points().into_iter().enumerate() {
        let root = fresh(&format!("writer_window_crash_{ordinal}"))?;
        let mut p = LocalRootPublisher::open(&root, limits())?;
        p.inject_crash_at(cut);
        let ns = namespace()?;
        let mut writer = HevcRecordingArchiveWriter::open(
            &mut p,
            ns.clone(),
            archive_limits(),
            0,
            100,
            &NeverCancel,
        )?;
        let admission = offer(&mut writer, 0, 0)?;
        assert!(writer.step(1, &NeverCancel).is_err());
        assert_eq!(writer.snapshot().windows().len(), 0);
        assert!(matches!(
            writer.retry(2, 100),
            Err(ArchiveError::Storage(RecordingIoError::ReopenRequired))
        ));
        let retired = writer.retire();
        let pending = retired.pending.ok_or("interrupted source lost")?;
        assert_eq!(pending.manifest().root(), admission.root);
        assert!(retired.prepared_page.is_none());
        drop(p);
        let mut p = LocalRootPublisher::open(&root, limits())?;
        if cut == PublishCutPoint::AfterRootTempWrite {
            assert!(p.root(&admission.slot).is_none());
            assert!(!p.recovery_report().orphaned_temps.is_empty());
            assert!(matches!(
                HevcRecordingArchiveWriter::open(
                    &mut p,
                    ns,
                    archive_limits(),
                    2,
                    100,
                    &NeverCancel
                ),
                Err(ArchiveError::RecoveryRequired)
            ));
            continue;
        }
        let mut recovered =
            HevcRecordingArchiveWriter::open(&mut p, ns, archive_limits(), 2, 100, &NeverCancel)?;
        if cut == PublishCutPoint::AfterRootRename {
            assert_eq!(recovered.snapshot().windows().len(), 1);
            assert_eq!(recovered.snapshot().unindexed_windows().len(), 1);
            assert_eq!(recovered.snapshot().windows()[0].root(), admission.root);
            drain(&mut recovered, 2)?;
            let size = pending.byte_len();
            assert!(matches!(
                *recovered
                    .offer(pending, size, 3)
                    .err()
                    .ok_or("lost ack duplicated window")?
                    .reason,
                ArchiveError::Duplicate
            ));
        } else {
            assert_eq!(recovered.snapshot().windows().len(), 0);
            let size = pending.byte_len();
            assert_eq!(recovered.offer(pending, size, 2)?.slot, admission.slot);
            assert!(matches!(
                recovered.step(2, &NeverCancel)?,
                ArchiveWriteProgress::WindowDurable { ordinal: 0, .. }
            ));
        }
        recovered.finish();
        drain(&mut recovered, 3)?;
        assert_eq!(recovered.snapshot().indexed_windows(), 1);
    }
    Ok(())
}

#[test]
fn all_catalog_root_crash_cuts_keep_prepared_page_and_reconcile_identical_roots() -> TestResult {
    for (ordinal, cut) in cut_points().into_iter().enumerate() {
        let (root, mut p, ns, _) = one_unindexed(&format!("writer_page_crash_{ordinal}"))?;
        p.inject_crash_at(cut);
        let mut writer = HevcRecordingArchiveWriter::open(
            &mut p,
            ns.clone(),
            archive_limits(),
            0,
            100,
            &NeverCancel,
        )?;
        assert!(matches!(
            writer.step(0, &NeverCancel)?,
            ArchiveWriteProgress::PageStarted { .. }
        ));
        assert!(matches!(
            writer.step(1, &NeverCancel)?,
            ArchiveWriteProgress::PageWindowVerified { .. }
        ));
        let ArchiveWriteProgress::CatalogPrepared { root: page_root } =
            writer.step(2, &NeverCancel)?
        else {
            return Err("page preparation missing".into());
        };
        assert!(matches!(
            writer.step(3, &NeverCancel)?,
            ArchiveWriteProgress::CatalogIndexStaged { .. }
        ));
        assert!(writer.step(4, &NeverCancel).is_err());
        assert_eq!(writer.snapshot().indexed_windows(), 0);
        let retired = writer.retire();
        assert!(retired.pending.is_none());
        let prepared = retired.prepared_page.ok_or("exact prepared page lost")?;
        assert_eq!(prepared.manifest().root(), page_root);
        drop(p);
        let mut p = LocalRootPublisher::open(&root, limits())?;
        if cut == PublishCutPoint::AfterRootTempWrite {
            assert!(matches!(
                HevcArchiveSnapshot::load(&p, ns, archive_limits(), &NeverCancel),
                Err(ArchiveError::RecoveryRequired)
            ));
            continue;
        }
        let mut writer = HevcRecordingArchiveWriter::open(
            &mut p,
            ns.clone(),
            archive_limits(),
            5,
            100,
            &NeverCancel,
        )?;
        if cut == PublishCutPoint::AfterRootRename {
            assert_eq!(writer.snapshot().indexed_windows(), 1);
            assert!(matches!(
                writer.step(5, &NeverCancel)?,
                ArchiveWriteProgress::Ready {
                    indexed_windows: 1,
                    ..
                }
            ));
        } else {
            assert_eq!(writer.snapshot().indexed_windows(), 0);
            let events = drain(&mut writer, 5)?;
            assert!(events.iter().any(|e| matches!(e, ArchiveWriteProgress::CatalogPrepared { root } if *root == page_root)));
        }
        assert_eq!(
            writer.snapshot().pages()[0].catalog().index_bytes(),
            prepared.index_bytes()
        );
        assert_eq!(
            writer.snapshot().pages()[0].catalog().manifest().root(),
            page_root
        );
        let retired = writer.retire();
        assert_eq!(retired.snapshot.pages().len(), 1);
        let receipt = p.publish(&ns.page_slot(0)?, prepared.manifest())?;
        assert_eq!(receipt.outcome, PublishOutcome::AlreadyPublished);
    }
    Ok(())
}

#[test]
fn explicit_flush_and_finish_publish_small_pages_without_extra_slots_or_hidden_work() -> TestResult
{
    let mut p = LocalRootPublisher::open(fresh("writer_manual_flush")?, limits())?;
    let ns = namespace()?;
    let mut writer = HevcRecordingArchiveWriter::open(
        &mut p,
        ns.clone(),
        archive_limits(),
        0,
        100,
        &NeverCancel,
    )?;
    writer.flush();
    assert!(matches!(
        writer.step(0, &NeverCancel)?,
        ArchiveWriteProgress::Ready {
            durable_windows: 0,
            indexed_windows: 0
        }
    ));
    offer(&mut writer, 0, 1)?;
    writer.flush();
    let events = drain(&mut writer, 1)?;
    assert!(events.iter().any(|e| matches!(
        e,
        ArchiveWriteProgress::CatalogPublished {
            first_ordinal: 0,
            windows: 1,
            ..
        }
    )));
    let next = offer(&mut writer, 90_000, 2)?;
    assert_eq!(next.slot, ns.window_slot(1)?);
    writer.finish();
    let late = fixture::window(180_000)?;
    let bytes = late.byte_len();
    assert!(matches!(
        *writer
            .offer(late, bytes, 2)
            .err()
            .ok_or("input after finish accepted")?
            .reason,
        ArchiveError::Closed
    ));
    let events = drain(&mut writer, 2)?;
    assert!(matches!(
        events.last(),
        Some(ArchiveWriteProgress::Finished {
            windows: 2,
            pages: 2,
            ..
        })
    ));
    let retired = writer.retire();
    assert!(retired.pending.is_none());
    assert!(retired.prepared_page.is_none());
    assert_eq!(p.visible_roots().count(), 4);
    Ok(())
}

#[test]
fn deadlines_and_reversed_clocks_preserve_exact_pending_window_for_explicit_retry() -> TestResult {
    let mut p = LocalRootPublisher::open(fresh("writer_time")?, limits())?;
    let mut writer = HevcRecordingArchiveWriter::open(
        &mut p,
        namespace()?,
        archive_limits(),
        5,
        10,
        &NeverCancel,
    )?;
    let admission = offer(&mut writer, 0, 5)?;
    assert!(matches!(
        writer.step(4, &NeverCancel),
        Err(ArchiveError::ClockReversed)
    ));
    assert_eq!(
        writer.pending().ok_or("pending lost")?.manifest().root(),
        admission.root
    );
    assert!(matches!(
        writer.step(10, &NeverCancel),
        Err(ArchiveError::Deadline)
    ));
    assert!(matches!(
        writer.step(11, &NeverCancel),
        Err(ArchiveError::Blocked)
    ));
    assert!(matches!(
        writer.retry(9, 100),
        Err(ArchiveError::ClockReversed)
    ));
    assert!(matches!(writer.retry(10, 10), Err(ArchiveError::Deadline)));
    writer.retry(10, 100)?;
    let ArchiveWriteProgress::WindowDurable { ordinal, receipt } = writer.step(10, &NeverCancel)?
    else {
        return Err("retry missing publication".into());
    };
    assert_eq!(ordinal, 0);
    assert_eq!(receipt.root, admission.root);
    writer.finish();
    drain(&mut writer, 11)?;
    assert_eq!(writer.snapshot().windows().len(), 1);
    Ok(())
}

#[test]
fn page_cancellation_retains_original_prepared_bytes_and_never_retracts_durable_windows()
-> TestResult {
    let (_, mut p, ns, _) = one_unindexed("writer_page_cancel")?;
    let mut writer =
        HevcRecordingArchiveWriter::open(&mut p, ns, archive_limits(), 0, 100, &NeverCancel)?;
    writer.step(0, &NeverCancel)?;
    writer.step(1, &NeverCancel)?;
    let ArchiveWriteProgress::CatalogPrepared { root } = writer.step(2, &NeverCancel)? else {
        return Err("page missing".into());
    };
    writer.step(3, &NeverCancel)?;
    assert!(matches!(
        writer.step(4, &Stop),
        Err(ArchiveError::Cancelled)
    ));
    assert_eq!(writer.snapshot().windows().len(), 1);
    assert_eq!(writer.snapshot().indexed_windows(), 0);
    writer.retry(5, 100)?;
    let ArchiveWriteProgress::CatalogPublished { receipt, .. } = writer.step(5, &NeverCancel)?
    else {
        return Err("exact retry did not publish".into());
    };
    assert_eq!(receipt.root, root);
    assert_eq!(
        writer.snapshot().pages()[0].catalog().manifest().root(),
        root
    );
    let retained = writer.retire();
    assert!(retained.pending.is_none());
    assert!(retained.prepared_page.is_none());
    assert_eq!(p.visible_roots().count(), 2);
    Ok(())
}

#[test]
fn corrupt_durable_media_is_not_promoted_to_a_discovery_page() -> TestResult {
    let root = fresh("writer_replay_before_page")?;
    let mut p = LocalRootPublisher::open(&root, limits())?;
    let ns = namespace()?;
    let w = fixture::window(0)?;
    let size = w.byte_len();
    let media = w.publication_plan().children()[2].1;
    let mut writer = HevcRecordingArchiveWriter::open(
        &mut p,
        ns.clone(),
        archive_limits(),
        0,
        100,
        &NeverCancel,
    )?;
    writer.offer(w, size, 0)?;
    assert!(matches!(
        writer.step(1, &NeverCancel)?,
        ArchiveWriteProgress::WindowDurable { .. }
    ));
    corrupt(&root, media)?;
    writer.flush();
    writer.step(2, &NeverCancel)?;
    assert!(writer.step(3, &NeverCancel).is_err());
    assert!(matches!(
        writer.step(4, &NeverCancel),
        Err(ArchiveError::Blocked)
    ));
    let retired = writer.retire();
    assert_eq!(retired.snapshot.windows().len(), 1);
    assert_eq!(retired.snapshot.indexed_windows(), 0);
    assert!(retired.prepared_page.is_none());
    assert!(p.root(&ns.page_slot(0)?).is_none());
    Ok(())
}

#[test]
fn fixed_capacity_and_flat_closure_limits_fail_without_eviction_or_ordinal_advance() -> TestResult {
    for by_pages in [false, true] {
        let mut p = LocalRootPublisher::open(
            fresh(if by_pages {
                "writer_page_bound"
            } else {
                "writer_window_bound"
            })?,
            limits(),
        )?;
        let bounds = ArchiveLimits {
            max_windows: if by_pages { 32 } else { 1 },
            max_pages: if by_pages { 1 } else { 32 },
            windows_per_page: 1,
            ..archive_limits()
        };
        let mut writer =
            HevcRecordingArchiveWriter::open(&mut p, namespace()?, bounds, 0, 100, &NeverCancel)?;
        offer(&mut writer, 0, 0)?;
        drain(&mut writer, 1)?;
        let w = fixture::window(90_000)?;
        let bytes = w.byte_len();
        let root = w.manifest().root();
        let failure = writer.offer(w, bytes, 2).err().ok_or("capacity ignored")?;
        assert!(matches!(*failure.reason, ArchiveError::Limit));
        assert_eq!(failure.recording.manifest().root(), root);
        assert_eq!(writer.snapshot().windows().len(), 1);
        assert!(writer.pending().is_none());
    }
    let mut tiny = limits();
    tiny.max_children = 4;
    let mut p = LocalRootPublisher::open(fresh("writer_flat_bound")?, tiny)?;
    assert!(matches!(
        HevcRecordingArchiveWriter::open(
            &mut p,
            namespace()?,
            archive_limits(),
            0,
            100,
            &NeverCancel
        ),
        Err(ArchiveError::Limit)
    ));
    assert_eq!(p.visible_roots().count(), 0);
    Ok(())
}

#[test]
fn existing_avc_aliases_and_progress_patterns_still_publish_recover_and_read() -> TestResult {
    let mut p = LocalRootPublisher::open(fresh("writer_avc_compatibility")?, limits())?;
    let w = recording_support::fixture(1, false)?.prepare()?;
    let root = w.manifest().root();
    let size = w.byte_len();
    let basis = CatalogScope {
        recording: w.summary().scope.clone(),
        decode_clock: ContentDigest::sha256(b"original-avc-decode-basis"),
        time_scale: 90_000,
    };
    let ns = ArchiveNamespace::new(basis)?;
    {
        let mut writer = RecordingArchiveWriter::open(
            &mut p,
            ns.clone(),
            archive_limits(),
            0,
            100,
            &NeverCancel,
        )?;
        assert_eq!(writer.offer(w, size, 0)?.ordinal, 0);
        writer.finish();
        let mut finished = false;
        for at in 0..16 {
            if matches!(
                writer.step(at, &NeverCancel)?,
                ArchiveWriteProgress::Finished {
                    windows: 1,
                    pages: 1,
                    ..
                }
            ) {
                finished = true;
                break;
            }
        }
        assert!(finished);
        let _: ArchiveRetirement = writer.retire();
    }
    let snapshot = ArchiveSnapshot::load(&p, ns, archive_limits(), &NeverCancel)?;
    let mut read = ArchiveRead::new(&p, &snapshot, 0..3600, ArchiveQueryLimits::default(), 100)?;
    // Preserve the old enum and its variant import path, not merely an opaque wrapper.
    use ArchiveReadProgress::{Complete, Window};
    let Window { recording, .. } = read.step(0, &NeverCancel)? else {
        return Err("AVC window missing".into());
    };
    assert_eq!(recording.manifest().root(), root);
    assert!(matches!(read.step(1, &NeverCancel)?, Complete(_)));
    Ok(())
}

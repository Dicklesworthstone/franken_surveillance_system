#![forbid(unsafe_code)]
//! Real HEVC TCP resets over the same native loopback/independent-store fixture.
//! Zero linger produces RST without unsafe code or a fabricated network error.

use super::*;
use fss_publication::{PublishCancellation, PublishCutPoint};
use fss_reference::rtsp::live_hevc::LiveHevcError;
use fss_reference::rtsp::tcp::TcpError;

fn interrupted_wire(fragmented: bool, count: usize) -> Test<Vec<u8>> {
    let mut out = interleaved(&packet(0, 0, false, &nals()?[0]).bytes)?;
    let mut sequence = 1;
    for p in packets()?.into_iter().take(count) {
        let nal = &p.bytes[12..];
        let ty = (nal[0] >> 1) & 63;
        let timestamp = u32::from_be_bytes(p.bytes[4..8].try_into()?);
        let payloads = if fragmented && ty <= 31 {
            let split = 2 + (nal.len() - 2) / 2;
            let mut first = vec![(nal[0] & 0x81) | (49 << 1), nal[1], 0x80 | ty];
            first.extend_from_slice(&nal[2..split]);
            let mut last = vec![(nal[0] & 0x81) | (49 << 1), nal[1], 0x40 | ty];
            last.extend_from_slice(&nal[split..]);
            vec![first, last]
        } else {
            vec![nal.to_vec()]
        };
        let total = payloads.len();
        for (i, payload) in payloads.into_iter().enumerate() {
            out.extend_from_slice(&interleaved(
                &packet(sequence, timestamp, i + 1 == total, &payload).bytes,
            )?);
            sequence += 1;
        }
    }
    Ok(out)
}

fn collect(f: &mut Fixture<'_>, fragmented: bool) -> Test {
    f.play()?;
    // IDR and P are closed by a REAL next-prefix VPS. That VPS remains source-only.
    f.peer.write_all(&interrupted_wire(fragmented, 6)?)?;
    for i in 0..2 {
        let request = f.next_timing()?;
        assert_eq!(request.rtp_timestamp, i as u32 * 18_000);
        let now = f.tick();
        let timed = f
            .driver
            .supply_timing(timings(2)[i], now, &f.authority, &NeverCancel)?;
        assert!(matches!(
            timed.admission,
            HevcCollectionAdmission::Accepted {
                window_ready: false,
                ..
            }
        ));
        f.timed.push(timed);
    }
    Ok(())
}

fn reset_reason(reason: &LiveHevcArchiveError) -> bool {
    matches!(
        reason,
        LiveHevcArchiveError::Network(LiveHevcError::Transport(TcpError::Io {
            operation: TcpOperation::Read,
            kind: std::io::ErrorKind::ConnectionReset,
        }))
    )
}
fn poll(
    driver: &mut JournaledLiveHevcArchive<'_, '_>,
    authority: &Authority,
    now: u64,
    cancel: &dyn PublishCancellation,
) -> Result<Step, LiveHevcArchiveFailure> {
    let credentials = DigestCredentials::new("test-user", "test-password").map_err(|_| {
        LiveHevcArchiveFailure {
            reason: LiveHevcArchiveError::Configuration,
            retirement: None,
        }
    })?;
    driver.poll(ready(), &credentials, [0; 16], now, authority, cancel)
}
fn until_admitted(
    driver: &mut JournaledLiveHevcArchive<'_, '_>,
    authority: &Authority,
    now: u64,
) -> Test<ArchiveAdmission> {
    for _ in 0..32_768 {
        match poll(driver, authority, now, &NeverCancel)? {
            Step::WindowAccepted(admission) => return Ok(admission),
            Step::Recording(_) => std::thread::yield_now(),
            _ => return Err("reset manufactured unrelated archive progress".into()),
        }
    }
    Err("reset preservation work bound".into())
}

#[test]
fn actual_reset_preserves_hevc_prefix_witness_and_cold_source() -> Test {
    for (chunk, fragmented, supplied) in [
        (7, false, false),
        (4096, false, true),
        (7, true, true),
        (4096, true, false),
    ] {
        let mut stores = Stores::new()?;
        let root = stores.root.clone();
        let namespace = stores.namespace.clone();
        let mut f = Fixture::bounded(
            &mut stores,
            selected()?,
            supplied.then(configuration).transpose()?,
            TcpLimits {
                chunk_bytes: chunk,
                ..TcpLimits::default()
            },
            MAX_RECORDING_BYTES,
        )?;
        collect(&mut f, fragmented)?;
        let Fixture {
            mut driver,
            peer,
            authority,
            now,
            ..
        } = f;
        peer.set_linger(Some(Duration::ZERO))?;
        drop(peer);
        let admission = until_admitted(&mut driver, &authority, now + 1)?;
        let plan = driver.pending().ok_or("preserved prefix")?;
        assert_eq!(plan.samples().len(), 2);
        assert_eq!(plan.source_only_nals(), 1);
        let source = plan.objects().source.to_vec();
        let media = plan.objects().media.to_vec();
        assert_eq!(driver.journal_anchor().sequence, 1);
        assert_eq!(driver.snapshot().ok_or("snapshot")?.windows().len(), 0);
        // Retiring input must end NETWORK authority, not the separate storage grant.
        authority.revoked.set(true);
        let checks = authority.checks.get();
        let mut candidate = false;
        let mut confirmed = false;
        let mut durable = false;
        let mut indexed = false;
        let mut finished = false;
        let mut terminal = None;
        for _ in 0..128 {
            match poll(&mut driver, &authority, LEASE + 1, &NeverCancel) {
                Ok(Step::Archive(progress)) => match *progress {
                    JournaledArchiveProgress::PinPersisted { .. } => {
                        candidate = true;
                        confirmed = false;
                    }
                    JournaledArchiveProgress::WorkConfirmed { .. } => {
                        assert!(candidate);
                        confirmed = true;
                    }
                    JournaledArchiveProgress::Archive(ArchiveWriteProgress::WindowDurable {
                        receipt,
                        ..
                    }) => {
                        assert!(confirmed);
                        assert_eq!(receipt.root, admission.root);
                        durable = true;
                    }
                    JournaledArchiveProgress::Archive(ArchiveWriteProgress::CatalogPublished {
                        ..
                    }) => {
                        assert!(durable && confirmed);
                        indexed = true;
                    }
                    JournaledArchiveProgress::Archive(ArchiveWriteProgress::Finished {
                        windows,
                        ..
                    }) => {
                        assert!(indexed && !finished);
                        assert_eq!(windows, 1);
                        finished = true;
                    }
                    _ => {}
                },
                Err(failure) => {
                    terminal = Some(failure);
                    break;
                }
                Ok(_) => {
                    return Err(
                        "interrupted capture claimed normal completion or polled input".into(),
                    );
                }
            }
        }
        let error = terminal.ok_or("original failure missing")?;
        assert!(finished && reset_reason(&error.reason));
        let retired = error.retirement.ok_or("terminal ownership")?;
        let input = retired.recording.ok_or("input retirement")?;
        let connection = input.connection.ok_or("original network state")?;
        assert!(!connection.transport.totals.peer_eof);
        let collection = input.capture.ok_or("capture remainder")?.collection;
        assert!(collection.pictures.is_empty() && collection.ready.is_none());
        // Native seal retains final media plus boundary lookahead, NOT an AVC-style cut.
        assert!(collection.sources.len() >= 2);
        assert_eq!(
            (collection.sources.last().ok_or("witness")?.bytes()[12] >> 1) & 63,
            32
        );
        let archive = retired.archive.ok_or("archive retirement")?;
        assert!(archive.writer.archive.pending.is_none());
        assert_eq!(archive.writer.archive.snapshot.indexed_windows(), 1);
        assert_eq!(authority.checks.get(), checks);
        assert!(matches!(
            poll(&mut driver, &authority, LEASE + 2, &NeverCancel)?,
            Step::Ended
        ));
        assert!(driver.cancel().is_none());
        drop(driver);
        drop(stores);
        let p = LocalRootPublisher::open(root, store_limits())?;
        let recording =
            load_hevc_recording(&p, &admission.slot, admission.root, &scope()?, &NeverCancel)?;
        assert_eq!(recording.objects().source, source);
        assert_eq!(recording.objects().media, media);
        let snapshot = HevcArchiveSnapshot::load(&p, namespace, archive_limits(), &NeverCancel)?;
        assert_eq!(snapshot.indexed_windows(), 1);
    }
    Ok(())
}

#[test]
fn empty_or_marker_only_reset_never_invents_a_closed_hevc_picture() -> Test {
    for count in [0, 4] {
        let mut stores = Stores::new()?;
        let mut f = Fixture::new(&mut stores, selected()?)?;
        f.play()?;
        if count != 0 {
            f.peer.write_all(&interrupted_wire(false, count)?)?;
        }
        // Drain every offered byte before closing peer; markers alone never yield TimingRequired.
        for _ in 0..32_768 {
            let Step::Recording(step) = f.poll(ready())? else {
                return Err("unexpected recording".into());
            };
            if matches!(*step, RecordingStep::Network(LiveHevcStep::Pending(_))) {
                break;
            }
            assert!(
                !matches!(*step, RecordingStep::Capture { event, .. } if matches!(*event, HevcCapturePoll::TimingRequired(_)))
            );
        }
        let Fixture {
            mut driver,
            peer,
            authority,
            now,
            ..
        } = f;
        peer.set_linger(Some(Duration::ZERO))?;
        drop(peer);
        let mut terminal = None;
        for _ in 0..32_768 {
            match poll(&mut driver, &authority, now + 1, &NeverCancel) {
                Err(error) => {
                    terminal = Some(error);
                    break;
                }
                Ok(Step::Recording(_)) => std::thread::yield_now(),
                _ => return Err("unverified HEVC tail became a recording".into()),
            }
        }
        let error = terminal.ok_or("reset not observed")?;
        assert!(reset_reason(&error.reason));
        let retired = error.retirement.ok_or("retirement")?;
        assert!(retired.interruption.is_none());
        assert!(
            retired
                .archive
                .ok_or("archive")?
                .writer
                .archive
                .snapshot
                .windows()
                .is_empty()
        );
        drop(driver);
        assert_eq!(stores.publisher.visible_roots().count(), 0);
        assert_eq!(stores.pins.anchor().sequence, 1);
    }
    Ok(())
}

#[test]
fn interrupted_cancel_returns_original_reason_and_pending_window_exactly_once() -> Test {
    let mut stores = Stores::new()?;
    let mut f = Fixture::new(&mut stores, selected()?)?;
    collect(&mut f, true)?;
    let Fixture {
        mut driver,
        peer,
        authority,
        now,
        ..
    } = f;
    peer.set_linger(Some(Duration::ZERO))?;
    drop(peer);
    let admitted = until_admitted(&mut driver, &authority, now + 1)?;
    let failure = driver.interruption().ok_or("interruption")?.kind;
    assert!(!driver.needs_credentials() && !driver.requires_authentication());
    assert!(
        !driver
            .interruption()
            .ok_or("interruption")?
            .seal
            .released
            .is_empty()
    );
    let retired = driver.cancel().ok_or("retirement")?;
    assert_eq!(retired.interruption.as_ref().map(|i| i.kind), Some(failure));
    assert_eq!(
        retired
            .archive
            .ok_or("archive")?
            .writer
            .archive
            .pending
            .ok_or("pending")?
            .manifest()
            .root(),
        admitted.root
    );
    assert!(driver.cancel().is_none());
    drop(driver);
    assert_eq!(stores.publisher.visible_roots().count(), 0);
    Ok(())
}

struct Cancel;
impl PublishCancellation for Cancel {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        true
    }
}
#[test]
fn storage_cancellation_and_pause_expiry_preserve_the_original_read_failure() -> Test {
    for cancel in [false, true] {
        let mut stores = Stores::new()?;
        let mut f = Fixture::new(&mut stores, selected()?)?;
        collect(&mut f, false)?;
        let Fixture {
            mut driver,
            peer,
            authority,
            now,
            ..
        } = f;
        peer.set_linger(Some(Duration::ZERO))?;
        drop(peer);
        let admitted = until_admitted(&mut driver, &authority, now + 1)?;
        let original = driver.interruption().ok_or("interruption")?.kind;
        let outcome = if cancel {
            poll(&mut driver, &authority, now + 2, &Cancel)
        } else {
            poll(
                &mut driver,
                &authority,
                now + 1 + 5_000_000_000,
                &NeverCancel,
            )
        };
        let error = outcome.err().ok_or("storage boundary ignored")?;
        if cancel {
            assert!(matches!(error.reason, LiveHevcArchiveError::Pins(_)));
        } else {
            assert!(matches!(
                error.reason,
                LiveHevcArchiveError::StoragePauseExpired
            ));
        }
        let retired = error.retirement.ok_or("retirement")?;
        assert_eq!(
            retired.interruption.as_ref().map(|i| i.kind),
            Some(original)
        );
        assert_eq!(
            retired
                .archive
                .ok_or("archive")?
                .writer
                .archive
                .pending
                .ok_or("pending")?
                .manifest()
                .root(),
            admitted.root
        );
        assert!(driver.cancel().is_none());
    }
    Ok(())
}

#[test]
fn preservation_output_ceiling_returns_exact_originals_and_the_rejected_window() -> Test {
    let mut stores = Stores::new()?;
    let mut f = Fixture::bounded(&mut stores, selected()?, None, TcpLimits::default(), 1)?;
    collect(&mut f, false)?;
    let Fixture {
        mut driver,
        peer,
        authority,
        now,
        ..
    } = f;
    peer.set_linger(Some(Duration::ZERO))?;
    drop(peer);
    let mut terminal = None;
    for _ in 0..32_768 {
        match poll(&mut driver, &authority, now + 1, &NeverCancel) {
            Err(error) => {
                terminal = Some(error);
                break;
            }
            Ok(Step::Recording(_)) => std::thread::yield_now(),
            _ => return Err("over-budget prefix admitted".into()),
        }
    }
    let error = terminal.ok_or("reset missing")?;
    assert!(matches!(error.reason, LiveHevcArchiveError::Archive(_)));
    let retired = error.retirement.ok_or("retirement")?;
    let interruption = retired.interruption.ok_or("original read receipt")?;
    assert_eq!(interruption.kind, std::io::ErrorKind::ConnectionReset);
    assert!(interruption.seal.window_ready);
    let window = retired.unoffered_window.ok_or("rejected original window")?;
    assert_eq!(window.samples().len(), 2);
    assert_eq!(window.source_only_nals(), 1);
    let collection = retired
        .recording
        .ok_or("recording")?
        .capture
        .ok_or("capture")?
        .collection;
    assert!(collection.pictures.is_empty() && collection.ready.is_none());
    // The ordinary native seal returns original datagrams separately from its
    // immutable prepared window. Check EVERY original, not just a nonzero count.
    let originals: Vec<_> = interruption
        .seal
        .released
        .iter()
        .chain(collection.sources.iter())
        .collect();
    let expected = packets()?;
    assert_eq!(originals.len(), 6);
    for (ordinal, (actual, expected)) in originals.iter().zip(&expected[..6]).enumerate() {
        let sequence = u16::try_from(ordinal + 1)?;
        let mut bytes = expected.bytes.clone();
        bytes[2..4].copy_from_slice(&sequence.to_be_bytes());
        assert_eq!(actual.sequence(), u64::from(sequence));
        assert_eq!(actual.bytes(), bytes);
    }
    assert!(
        retired
            .archive
            .ok_or("archive")?
            .writer
            .archive
            .pending
            .is_none()
    );
    Ok(())
}

#[test]
fn interrupted_drain_refuses_new_input_without_replacing_failure_or_resetting_clock() -> Test {
    let mut stores = Stores::new()?;
    let mut f = Fixture::new(&mut stores, selected()?)?;
    collect(&mut f, false)?;
    let Fixture {
        mut driver,
        peer,
        authority,
        now,
        ..
    } = f;
    peer.set_linger(Some(Duration::ZERO))?;
    drop(peer);
    let admitted = until_admitted(&mut driver, &authority, now + 1)?;
    let original = driver.interruption().ok_or("interruption")?.kind;
    let errors = [
        driver.seal(now + 2, &authority, &NeverCancel).err(),
        driver.flush(now + 2, &authority, &NeverCancel).err(),
        driver
            .finish_capture(now + 2, &authority, &NeverCancel)
            .err(),
        driver
            .supply_timing(timings(1)[0], now + 2, &authority, &NeverCancel)
            .err(),
    ];
    for error in errors {
        let error = error.ok_or("input admitted after read failure")?;
        assert!(matches!(error.reason, LiveHevcArchiveError::Closed));
        assert!(error.retirement.is_none());
    }
    let error = poll(&mut driver, &authority, now, &NeverCancel)
        .err()
        .ok_or("reversed clock admitted")?;
    assert!(matches!(error.reason, LiveHevcArchiveError::ClockReversed));
    assert!(error.retirement.is_none());
    assert_eq!(driver.interruption().map(|i| i.kind), Some(original));
    assert_eq!(
        driver.pending().ok_or("pending")?.manifest().root(),
        admitted.root
    );
    assert!(!driver.needs_credentials());
    Ok(())
}

#[test]
fn revoked_live_grant_never_becomes_prefix_preservation() -> Test {
    let mut stores = Stores::new()?;
    let mut f = Fixture::new(&mut stores, selected()?)?;
    collect(&mut f, false)?;
    let Fixture {
        mut driver,
        peer,
        authority,
        now,
        ..
    } = f;
    authority.revoked.set(true);
    peer.set_linger(Some(Duration::ZERO))?;
    drop(peer);
    let error = poll(&mut driver, &authority, now + 1, &NeverCancel)
        .err()
        .ok_or("revoked network owner progressed")?;
    assert!(matches!(
        error.reason,
        LiveHevcArchiveError::Authority(TcpDenial::Revoked)
    ));
    let retired = error.retirement.ok_or("retirement")?;
    assert!(retired.interruption.is_none());
    assert_eq!(
        retired
            .recording
            .ok_or("recording")?
            .capture
            .ok_or("capture")?
            .collection
            .pictures
            .len(),
        2
    );
    assert!(
        retired
            .archive
            .ok_or("archive")?
            .writer
            .archive
            .pending
            .is_none()
    );
    drop(driver);
    assert_eq!(stores.publisher.visible_roots().count(), 0);
    assert_eq!(stores.pins.anchor().sequence, 1);
    Ok(())
}

#[test]
fn held_untimed_picture_prevents_reading_a_reset_or_sealing_earlier_work() -> Test {
    let mut stores = Stores::new()?;
    let mut f = Fixture::new(&mut stores, selected()?)?;
    f.play()?;
    f.peer.write_all(&interrupted_wire(false, 6)?)?;
    let _ = f.next_timing()?;
    let now = f.tick();
    let timed = f
        .driver
        .supply_timing(timings(1)[0], now, &f.authority, &NeverCancel)?;
    f.timed.push(timed);
    let held = f.next_timing()?;
    let Fixture {
        mut driver,
        peer,
        authority,
        now,
        ..
    } = f;
    let before = driver.totals().ok_or("totals")?;
    peer.set_linger(Some(Duration::ZERO))?;
    drop(peer);
    let Step::Recording(step) = poll(&mut driver, &authority, now + 1, &NeverCancel)? else {
        return Err("untimed picture was bypassed".into());
    };
    assert!(matches!(*step, RecordingStep::Capture { event, .. }
        if matches!(*event, HevcCapturePoll::TimingRequired(request) if request == held)));
    assert_eq!(driver.totals().ok_or("totals")?, before);
    assert!(driver.interruption().is_none());
    let retired = driver.cancel().ok_or("retirement")?;
    let capture = retired
        .recording
        .ok_or("recording")?
        .capture
        .ok_or("capture")?;
    assert_eq!(capture.collection.pictures.len(), 1);
    assert!(capture.event.is_some());
    assert!(
        retired
            .archive
            .ok_or("archive")?
            .writer
            .archive
            .pending
            .is_none()
    );
    Ok(())
}

#[test]
fn interrupted_hevc_work_recovers_cold_before_normal_window_publication() -> Test {
    let mut stores = Stores::new()?;
    let root = stores.root.clone();
    let mut f = Fixture::new(&mut stores, selected()?)?;
    collect(&mut f, true)?;
    let Fixture {
        mut driver,
        peer,
        authority,
        now,
        ..
    } = f;
    peer.set_linger(Some(Duration::ZERO))?;
    drop(peer);
    let admitted = until_admitted(&mut driver, &authority, now + 1)?;
    let source = driver.pending().ok_or("pending")?.objects().source.to_vec();
    let mut confirmed = None;
    for _ in 0..16 {
        let Step::Archive(progress) = poll(&mut driver, &authority, now + 2, &NeverCancel)? else {
            return Err("protected drain polled input".into());
        };
        match *progress {
            JournaledArchiveProgress::PinPersisted { .. } => {}
            JournaledArchiveProgress::WorkConfirmed { checkpoint, .. } => {
                confirmed = Some(checkpoint);
                break;
            }
            _ => return Err("normal publication preceded confirmed recovery work".into()),
        }
    }
    let confirmed = confirmed.ok_or("work confirmation")?;
    assert!(driver.snapshot().ok_or("snapshot")?.windows().is_empty());
    let retired = driver.cancel().ok_or("retirement")?;
    assert!(retired.interruption.is_some());
    drop(retired);
    drop(driver);
    drop(stores);
    let publisher = LocalRootPublisher::open(&root, store_limits())?;
    assert!(publisher.root(&admitted.slot).is_none());
    let work = load_hevc_archive_work(
        &publisher,
        confirmed.slot(),
        confirmed.root(),
        ArchiveWorkLimits::default(),
        &NeverCancel,
    )?;
    let pending = work.pending.ok_or("cold HEVC prefix missing")?;
    assert_eq!(pending.manifest().root(), admitted.root);
    assert_eq!(pending.objects().source, source);
    assert_eq!(pending.samples().len(), 2);
    assert_eq!(pending.source_only_nals(), 1);
    Ok(())
}

#![forbid(unsafe_code)]
//! Real loopback collection/publication with a deterministic terminal-error seam.
//! Retire the actual native owner, then inject a typed failure at archive admission.
//! These are not OS-level TCP-reset tests; source and picture proofs remain native.

use super::*;
use crate::rtsp::live_avc::LiveAvcError;
use crate::rtsp::tcp::TcpError;
use std::io::ErrorKind;

fn read_reset() -> LiveRecordingError {
    LiveRecordingError::Network(LiveAvcError::Transport(TcpError::Io {
        operation: TcpOperation::Read,
        kind: ErrorKind::ConnectionReset,
    }))
}

fn interrupted(
    f: &mut Fixture<'_>,
    reason: LiveRecordingError,
    now: u64,
) -> Test<LiveRecordingFailure> {
    // Reproduce the native poll seam: outer admission occurred, and the recording
    // owner's fatal read closed its actual socket and transferred every layer.
    f.driver.admit(now, &f.authority)?;
    let retired = f
        .driver
        .recording
        .as_mut()
        .ok_or("recording owner")?
        .cancel()
        .ok_or("native recording retirement")?;
    assert!(retired.connection.is_some());
    Ok(LiveRecordingFailure {
        reason,
        retirement: Some(Box::new(retired)),
    })
}

fn collected(f: &mut Fixture<'_>) -> Test {
    f.picture()?;
    let _ = f.driver.supply_timing(timing(), 12, &f.authority)?;
    assert!(f.driver.pending().is_none());
    assert_eq!(f.driver.snapshot().ok_or("snapshot")?.windows().len(), 0);
    Ok(())
}

fn preserved(f: &mut Fixture<'_>, now: u64) -> Test<ArchiveAdmission> {
    let error = interrupted(f, read_reset(), now)?;
    match f.driver.preserve_read_failure(error, now)? {
        LiveArchiveStep::WindowAccepted(admission) => Ok(admission),
        _ => Err("verified prefix was not accepted by the original writer".into()),
    }
}

#[test]
fn abrupt_read_preserves_a_verified_window_and_catalog_but_never_successful_capture() -> Test {
    for chunk in [7, 4096] {
        let path = fresh()?;
        let mut publisher = LocalRootPublisher::open(&path, limits())?;
        let mut f = Fixture::playing(&mut publisher, chunk, 4)?;
        collected(&mut f)?;
        let admission = preserved(&mut f, 13)?;
        let scope = f.namespace.scope().recording.clone();
        let expected = f.driver.pending().ok_or("accepted prefix")?;
        let expected_source = expected.objects().source.to_vec();
        let expected_media = expected.objects().media.to_vec();
        assert_eq!(expected.manifest().root(), admission.root);
        assert_eq!(f.driver.state(), ClientState::Closed);
        assert_eq!(f.driver.interruption(), Some(&read_reset()));
        assert!(f.driver.completion.is_none());
        assert!(f.driver.totals().is_none());
        assert_eq!(
            f.peer.read(&mut [0; 1])?,
            0,
            "the actual socket must already be closed"
        );

        // Revoking the retired network grant does not revoke the independent
        // storage owner. No network probe or socket operation may occur in drain.
        f.authority.revoked.set(true);
        let checks = f.authority.checks.get();
        let mut windows = 0;
        let mut catalogs = 0;
        let mut witnesses = 0;
        let mut terminal = None;
        for _ in 0..32 {
            match f.driver.poll(
                SocketReadiness {
                    readable: true,
                    writable: true,
                },
                14,
                &f.authority,
                &NeverCancel,
            ) {
                Ok(LiveArchiveStep::Archive(ArchiveWriteProgress::WindowDurable { .. })) => {
                    windows += 1
                }
                Ok(LiveArchiveStep::Archive(ArchiveWriteProgress::CatalogPublished { .. })) => {
                    catalogs += 1
                }
                Ok(LiveArchiveStep::Archive(ArchiveWriteProgress::Finished {
                    windows: 1,
                    pages: 1,
                    ..
                })) => {
                    witnesses += 1;
                    assert_eq!(f.driver.interruption(), Some(&read_reset()));
                }
                Ok(LiveArchiveStep::Archive(_)) => {}
                Err(error) => {
                    terminal = Some(error);
                    break;
                }
                Ok(_) => {
                    return Err("read failure became network work, EOF or capture success".into());
                }
            }
        }
        assert_eq!((windows, catalogs, witnesses), (1, 1, 1));
        assert_eq!(f.authority.checks.get(), checks);
        let error = terminal.ok_or("original failure did not terminate the drain")?;
        assert!(
            matches!(&error.reason, LiveArchiveError::Recording(reason) if **reason == read_reset())
        );
        let retired = error.retirement.ok_or("final retirement")?;
        assert_eq!(retired.interruption.as_ref(), Some(&read_reset()));
        let recording = retired
            .recording
            .as_ref()
            .ok_or("original network retirement")?;
        assert!(recording.connection.is_some());
        assert!(recording.capture.collection.pending.pictures.is_empty());
        assert!(recording.capture.collection.pending.sources.is_empty());
        let archived = retired.archive.as_ref().ok_or("archive retirement")?;
        assert!(archived.pending.is_none());
        assert_eq!(archived.snapshot.windows().len(), 1);
        assert_eq!(archived.snapshot.indexed_windows(), 1);
        assert!(f.driver.cancel().is_none());
        assert!(matches!(
            f.driver
                .poll(SocketReadiness::default(), 15, &f.authority, &NeverCancel)?,
            LiveArchiveStep::Ended
        ));
        drop(f);
        drop(publisher);
        let publisher = LocalRootPublisher::open(&path, limits())?;
        let window = load_recording(
            &publisher,
            &admission.slot,
            admission.root,
            &scope,
            &NeverCancel,
        )?;
        assert_eq!(window.objects().source, expected_source);
        assert_eq!(window.objects().media, expected_media);
    }
    Ok(())
}

struct StopStorage;
impl PublishCancellation for StopStorage {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        true
    }
}

#[test]
fn storage_cancellation_preserves_both_causes_and_the_original_pending_window() -> Test {
    let mut publisher = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::playing(&mut publisher, 4096, 4)?;
    collected(&mut f)?;
    let admission = preserved(&mut f, 13)?;
    let error = f
        .driver
        .poll(SocketReadiness::default(), 14, &f.authority, &StopStorage)
        .err()
        .ok_or("cancelled storage advanced")?;
    assert!(matches!(
        error.reason,
        LiveArchiveError::Archive(ArchiveError::Cancelled)
    ));
    let retired = error.retirement.ok_or("cancelled retirement")?;
    assert_eq!(retired.interruption.as_ref(), Some(&read_reset()));
    let archive = retired.archive.as_ref().ok_or("archive ownership")?;
    assert_eq!(
        archive
            .pending
            .as_ref()
            .ok_or("pending verified prefix")?
            .manifest()
            .root(),
        admission.root
    );
    assert!(archive.snapshot.windows().is_empty());
    assert!(f.driver.cancel().is_none());
    drop(f);
    assert_eq!(publisher.visible_roots().count(), 0);
    Ok(())
}

#[test]
fn explicit_cancel_returns_pending_prefix_without_writes_or_duplicate_retirement() -> Test {
    let mut publisher = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::playing(&mut publisher, 4096, 4)?;
    collected(&mut f)?;
    let admission = preserved(&mut f, 13)?;
    let retired = f.driver.cancel().ok_or("explicit retirement")?;
    assert_eq!(retired.interruption.as_ref(), Some(&read_reset()));
    assert!(
        retired
            .recording
            .as_ref()
            .ok_or("recording remainder")?
            .connection
            .is_some()
    );
    assert_eq!(
        retired
            .archive
            .as_ref()
            .ok_or("archive")?
            .pending
            .as_ref()
            .ok_or("pending prefix")?
            .manifest()
            .root(),
        admission.root
    );
    assert!(f.driver.cancel().is_none());
    drop(f);
    assert_eq!(publisher.visible_roots().count(), 0);
    Ok(())
}

#[test]
fn held_untimed_picture_and_small_output_ceiling_do_not_lose_originals() -> Test {
    for untimed in [true, false] {
        let mut publisher = LocalRootPublisher::open(fresh()?, limits())?;
        let mut f = Fixture::playing(&mut publisher, 4096, 4)?;
        if untimed {
            f.picture()?;
        } else {
            collected(&mut f)?;
            f.driver.max_window_bytes = 1;
        }
        let failure = interrupted(&mut f, read_reset(), 13)?;
        let before = failure
            .retirement
            .as_ref()
            .ok_or("retirement")?
            .capture
            .collection
            .pending
            .sources
            .iter()
            .map(|s| (s.sequence(), s.received_ns(), s.bytes().to_vec()))
            .collect::<Vec<_>>();
        let error = f
            .driver
            .preserve_read_failure(failure, 13)
            .err()
            .ok_or("ineligible prefix was prepared")?;
        let retired = error.retirement.ok_or("unchanged retirement")?;
        let recording = retired.recording.as_ref().ok_or("original recording")?;
        assert_eq!(recording.capture.picture.is_some(), untimed);
        assert_eq!(
            recording
                .capture
                .collection
                .pending
                .sources
                .iter()
                .map(|s| (s.sequence(), s.received_ns(), s.bytes().to_vec()))
                .collect::<Vec<_>>(),
            before
        );
        assert!(retired.archive.as_ref().ok_or("archive")?.pending.is_none());
        drop(f);
        assert_eq!(publisher.visible_roots().count(), 0);
    }
    Ok(())
}

#[test]
fn authority_and_non_read_failures_do_not_trigger_automatic_preservation() -> Test {
    for transport in [
        TcpError::Denied(TcpDenial::Revoked),
        TcpError::Denied(TcpDenial::Cancelled),
        TcpError::Deadline,
        TcpError::WorkBudget,
        TcpError::Io {
            operation: TcpOperation::Write,
            kind: ErrorKind::ConnectionReset,
        },
        TcpError::Io {
            operation: TcpOperation::Read,
            kind: ErrorKind::TimedOut,
        },
    ] {
        let mut publisher = LocalRootPublisher::open(fresh()?, limits())?;
        let mut f = Fixture::playing(&mut publisher, 4096, 4)?;
        collected(&mut f)?;
        let reason = LiveRecordingError::Network(LiveAvcError::Transport(transport));
        let failure = interrupted(&mut f, reason.clone(), 13)?;
        let error = f
            .driver
            .preserve_read_failure(failure, 13)
            .err()
            .ok_or("non-read failure admitted new archival work")?;
        assert!(matches!(&error.reason, LiveArchiveError::Recording(actual) if **actual == reason));
        let retired = error.retirement.ok_or("native failure retirement")?;
        assert_eq!(
            retired
                .recording
                .as_ref()
                .ok_or("recording")?
                .capture
                .collection
                .pending
                .pictures
                .len(),
            1
        );
        assert!(retired.archive.as_ref().ok_or("archive")?.pending.is_none());
        assert!(retired.interruption.is_none());
        drop(f);
        assert_eq!(publisher.visible_roots().count(), 0);
    }
    Ok(())
}

#[test]
fn preservation_keeps_storage_deadline_pause_and_work_allowance_unchanged() -> Test {
    let mut publisher = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::playing(&mut publisher, 4096, 4)?;
    collected(&mut f)?;
    let storage_deadline = f.driver.publication_deadline_ns;
    let before = f.driver.remaining_steps;
    let _ = preserved(&mut f, 13)?;
    assert_eq!(f.driver.remaining_steps, before - 1); // one original poll admission
    assert_eq!(f.driver.publication_deadline_ns, storage_deadline);
    assert_eq!(f.driver.storage_since_ns, Some(13));
    let remaining = f.driver.remaining_steps;
    let error = f
        .driver
        .poll(SocketReadiness::default(), 12, &f.authority, &NeverCancel)
        .err()
        .ok_or("reversed clock accepted")?;
    assert!(matches!(error.reason, LiveArchiveError::ClockReversed));
    assert!(error.retirement.is_none());
    assert_eq!(f.driver.remaining_steps, remaining);
    assert_eq!(f.driver.interruption(), Some(&read_reset()));
    let expiration = 13 + f.driver.max_storage_pause_ns;
    let error = f
        .driver
        .poll(
            SocketReadiness::default(),
            expiration,
            &f.authority,
            &NeverCancel,
        )
        .err()
        .ok_or("expired preservation pause was renewed")?;
    assert!(matches!(
        error.reason,
        LiveArchiveError::StoragePauseExpired
    ));
    assert_eq!(
        error
            .retirement
            .as_ref()
            .ok_or("expired retirement")?
            .interruption
            .as_ref(),
        Some(&read_reset())
    );
    drop(f);
    assert_eq!(publisher.visible_roots().count(), 0);
    Ok(())
}

#[test]
fn interrupted_finalization_cannot_accept_an_owner_stop_or_new_command() -> Test {
    let mut publisher = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::playing(&mut publisher, 4096, 4)?;
    collected(&mut f)?;
    let _ = preserved(&mut f, 13)?;
    let error = f
        .driver
        .finish_capture(14, &f.authority)
        .err()
        .ok_or("interruption became owner stop")?;
    assert!(matches!(error.reason, LiveArchiveError::Closed));
    assert!(error.retirement.is_none());
    assert!(f.driver.completion.is_none());
    let error = f
        .driver
        .request(
            ClientCommand::Describe,
            &credentials()?,
            [0; 16],
            14,
            &f.authority,
        )
        .err()
        .ok_or("interrupted capture prepared a command")?;
    assert!(matches!(error.reason, LiveArchiveError::Closed));
    assert!(error.retirement.is_none());
    assert_eq!(f.driver.interruption(), Some(&read_reset()));
    assert_eq!(f.peer.read(&mut [0; 1])?, 0);
    Ok(())
}

#[test]
fn nonterminal_archive_progress_cannot_be_mislabeled_as_a_final_snapshot() -> Test {
    let mut publisher = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::playing(&mut publisher, 4096, 4)?;
    collected(&mut f)?;
    let admission = preserved(&mut f, 13)?;
    let error = f
        .driver
        .finish_archive(ArchiveWriteProgress::Ready {
            durable_windows: 0,
            indexed_windows: 0,
        })
        .err()
        .ok_or("nonterminal progress was emitted as a final witness")?;
    assert!(matches!(error.reason, LiveArchiveError::Invariant));
    let retired = error.retirement.ok_or("invalid completion retirement")?;
    assert_eq!(retired.interruption.as_ref(), Some(&read_reset()));
    assert_eq!(
        retired
            .archive
            .as_ref()
            .ok_or("archive")?
            .pending
            .as_ref()
            .ok_or("pending window")?
            .manifest()
            .root(),
        admission.root
    );
    drop(f);
    assert_eq!(publisher.visible_roots().count(), 0);
    Ok(())
}

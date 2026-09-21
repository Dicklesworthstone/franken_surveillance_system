#![forbid(unsafe_code)]
//! Recovery drives only exact retained storage work; no second camera connection.
use super::*;
use crate::rtsp::archive_recovery::{ArchiveResumeConfig, ArchiveResumeProgress,
    RecordingArchiveResume, RetiredPublicationState, archive_retirement_digest};
use crate::rtsp::recording::local::{RecordingPublication, RecordingProgress};

fn resume_config(retired: &ArchiveRetirement) -> Test<ArchiveResumeConfig> {
    Ok(ArchiveResumeConfig { expected_retirement_digest: archive_retirement_digest(retired)?,
        max_window_bytes: MAX_RECORDING_BYTES, max_steps: 256, deadline_ns: 1_000 })
}
fn complete(resume: &mut RecordingArchiveResume<'_>, now: u64) -> Test<Vec<ArchiveResumeProgress>> {
    let mut all = Vec::new();
    for _ in 0..128 {
        let step = resume.step(now, &NeverCancel)?;
        let finished = matches!(&step, ArchiveResumeProgress::Archive(ArchiveWriteProgress::Finished { .. }));
        all.push(step); if finished { return Ok(all); }
    }
    Err("bounded resumed archive did not finish".into())
}
fn publish_exact(p: &mut LocalRootPublisher, slot: fss_publication::SlotName, window: &PreparedRecording) -> Test {
    let mut job = RecordingPublication::new(window, p, slot, window.byte_len(), 1_000)?;
    for _ in 0..5 {
        if let RecordingProgress::Published(_) = job.step(20, &NeverCancel)? { return Ok(()); }
    }
    Err("original publication did not finish".into())
}

#[test]
fn unpublished_original_is_resumed_once_at_the_reserved_ordinal_without_camera_io() -> Test {
    let path = fresh()?; let mut p = LocalRootPublisher::open(&path, limits())?;
    let mut f = Fixture::playing(&mut p, 7, 4)?; let admission = f.window()?;
    let retired = f.driver.cancel().ok_or("retirement")?.archive.ok_or("archive")?;
    let config = resume_config(&retired)?; drop(f); drop(p);
    let mut p = LocalRootPublisher::open(&path, limits())?;
    let mut resume = RecordingArchiveResume::open(&mut p, retired, config, 20, &NeverCancel)?;
    assert_eq!(resume.reconciliation().window, RetiredPublicationState::NotPublished(admission.root));
    assert_eq!(resume.snapshot().windows().len(), 0);
    let outputs = complete(&mut resume, 21)?;
    assert_eq!(outputs.iter().filter(|s| matches!(s, ArchiveResumeProgress::WindowAccepted(_))).count(), 1);
    assert_eq!(resume.snapshot().windows().len(), 1); assert_eq!(resume.snapshot().indexed_windows(), 1);
    assert_eq!(resume.snapshot().windows()[0].slot(), &admission.slot);
    assert!(matches!(resume.step(22, &NeverCancel)?, ArchiveResumeProgress::Ended));
    Ok(())
}

#[test]
fn lost_window_ack_is_reconciled_as_durable_without_duplicate_or_republication() -> Test {
    let path = fresh()?; let mut p = LocalRootPublisher::open(&path, limits())?;
    p.inject_crash_at(PublishCutPoint::AfterRootRename);
    let mut f = Fixture::playing(&mut p, 4096, 4)?; let admission = f.window()?;
    let error = f.driver.poll(SocketReadiness::default(), 14, &f.authority, &NeverCancel)
        .err().ok_or("injected publication fault did not stop capture")?;
    let retired = error.retirement.ok_or("retirement")?.archive.ok_or("archive")?;
    assert_eq!(retired.snapshot.windows().len(), 0);
    assert_eq!(retired.pending.as_ref().ok_or("pending")?.manifest().root(), admission.root);
    let config = resume_config(&retired)?; drop(f); drop(p);
    let mut p = LocalRootPublisher::open(&path, limits())?;
    let mut resume = RecordingArchiveResume::open(&mut p, retired, config, 20, &NeverCancel)?;
    assert_eq!(resume.reconciliation().window, RetiredPublicationState::AlreadyDurable(admission.root));
    assert!(resume.pending().is_none());
    let outputs = complete(&mut resume, 21)?;
    assert!(!outputs.iter().any(|s| matches!(s, ArchiveResumeProgress::WindowAccepted(_)
        | ArchiveResumeProgress::Archive(ArchiveWriteProgress::WindowDurable { .. }))));
    assert_eq!(resume.snapshot().windows().len(), 1); assert_eq!(resume.snapshot().indexed_windows(), 1);
    Ok(())
}

#[test]
fn lost_catalog_ack_recovers_the_exact_page_without_preparing_a_replacement() -> Test {
    let path = fresh()?; let mut p = LocalRootPublisher::open(&path, limits())?;
    let mut f = Fixture::playing(&mut p, 4096, 4)?; f.window()?; f.storage(14)?;
    let retired = f.driver.cancel().ok_or("retirement")?.archive.ok_or("archive")?;
    assert_eq!(retired.snapshot.indexed_windows(), 0);
    let config = resume_config(&retired)?; drop(f); drop(p);
    let mut p = LocalRootPublisher::open(&path, limits())?; p.inject_crash_at(PublishCutPoint::AfterRootRename);
    let mut resume = RecordingArchiveResume::open(&mut p, retired, config, 20, &NeverCancel)?;
    let mut prepared = None; let mut failed = false;
    for _ in 0..128 {
        match resume.step(21, &NeverCancel) {
            Ok(ArchiveResumeProgress::Archive(ArchiveWriteProgress::CatalogPrepared { root })) => prepared = Some(root),
            Ok(_) => {}, Err(_) => { failed = true; break; }
        }
    }
    assert!(failed); let root = prepared.ok_or("prepared catalog")?;
    let retired = resume.retire().into_retry().map_err(|_| "competing retained pages")?;
    assert_eq!(retired.prepared_page.as_ref().ok_or("original page lost")?.manifest().root(), root);
    let config = resume_config(&retired)?; drop(p);
    let mut p = LocalRootPublisher::open(&path, limits())?;
    let mut resume = RecordingArchiveResume::open(&mut p, retired, config, 30, &NeverCancel)?;
    assert_eq!(resume.reconciliation().page, RetiredPublicationState::AlreadyDurable(root));
    let outputs = complete(&mut resume, 31)?;
    assert!(!outputs.iter().any(|s| matches!(s, ArchiveResumeProgress::Archive(
        ArchiveWriteProgress::CatalogPrepared { .. } | ArchiveWriteProgress::CatalogPublished { .. }))));
    assert_eq!(resume.snapshot().pages().len(), 1);
    Ok(())
}

#[test]
fn unresolved_root_temp_is_not_deleted_or_mistaken_for_absence() -> Test {
    let path = fresh()?; let mut p = LocalRootPublisher::open(&path, limits())?;
    p.inject_crash_at(PublishCutPoint::AfterRootTempWrite);
    let mut f = Fixture::playing(&mut p, 4096, 1)?; let admission = f.window()?;
    let error = f.driver.poll(SocketReadiness::default(), 14, &f.authority, &NeverCancel)
        .err().ok_or("injected temporary did not stop capture")?;
    let retired = error.retirement.ok_or("retirement")?.archive.ok_or("archive")?;
    let config = resume_config(&retired)?; drop(f); drop(p);
    let mut p = LocalRootPublisher::open(&path, limits())?;
    let temps = p.recovery_report().orphaned_temps.clone(); assert!(!temps.is_empty());
    let refusal = RecordingArchiveResume::open(&mut p, retired, config, 20, &NeverCancel)
        .err().ok_or("unresolved temporary adopted")?;
    assert_eq!(refusal.retired.pending.as_ref().ok_or("pending")?.manifest().root(), admission.root);
    assert_eq!(p.recovery_report().orphaned_temps, temps);
    for temp in temps { assert!(path.join(&temp).exists()); }
    Ok(())
}

#[test]
fn pre_root_crash_keeps_original_bytes_for_explicit_republication() -> Test {
    for cut in [PublishCutPoint::AfterChildrenVerified, PublishCutPoint::AfterManifestBody] {
        let path = fresh()?; let mut p = LocalRootPublisher::open(&path, limits())?;
        p.inject_crash_at(cut);
        let mut f = Fixture::playing(&mut p, 4096, 1)?; let admission = f.window()?;
        let error = f.driver.poll(SocketReadiness::default(), 14, &f.authority, &NeverCancel)
            .err().ok_or("injected pre-root failure missing")?;
        let retired = error.retirement.ok_or("retirement")?.archive.ok_or("archive")?;
        let config = resume_config(&retired)?; drop(f); drop(p);
        let mut p = LocalRootPublisher::open(&path, limits())?;
        let mut resume = RecordingArchiveResume::open(&mut p, retired, config, 20, &NeverCancel)?;
        assert_eq!(resume.reconciliation().window, RetiredPublicationState::NotPublished(admission.root));
        complete(&mut resume, 21)?;
        assert_eq!(resume.snapshot().windows()[0].root(), admission.root);
    }
    Ok(())
}

#[test]
fn wrong_retirement_pin_refuses_without_consuming_the_original_or_writing_storage() -> Test {
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::playing(&mut p, 4096, 1)?; let admission = f.window()?;
    let retired = f.driver.cancel().ok_or("retirement")?.archive.ok_or("archive")?;
    let mut config = resume_config(&retired)?; config.expected_retirement_digest = ContentDigest::sha256(b"wrong pin");
    drop(f);
    let refusal = RecordingArchiveResume::open(&mut p, retired, config, 20, &NeverCancel)
        .err().ok_or("wrong pin admitted")?;
    assert_eq!(refusal.retired.pending.as_ref().ok_or("lost pending")?.manifest().root(), admission.root);
    assert_eq!(p.visible_roots().count(), 0); Ok(())
}

#[test]
fn missing_acknowledged_roots_are_not_silently_recreated_from_pending_input() -> Test {
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::playing(&mut p, 4096, 4)?; f.window()?; f.storage(14)?;
    let retired = f.driver.cancel().ok_or("retirement")?.archive.ok_or("archive")?;
    let config = resume_config(&retired)?; drop(f);
    let mut other = LocalRootPublisher::open(fresh()?, limits())?;
    let refusal = RecordingArchiveResume::open(&mut other, retired, config, 20, &NeverCancel)
        .err().ok_or("missing prefix accepted")?;
    assert!(matches!(refusal.reason, ArchiveError::Sequence));
    assert_eq!(refusal.retired.snapshot.windows().len(), 1);
    assert_eq!(other.visible_roots().count(), 0); Ok(())
}

#[test]
fn recovered_pending_slot_cannot_name_different_valid_recording_bytes() -> Test {
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::playing(&mut p, 4096, 1)?; let admission = f.window()?;
    let retired = f.driver.cancel().ok_or("retirement")?.archive.ok_or("archive")?;
    let config = resume_config(&retired)?; drop(f);
    let mut q = LocalRootPublisher::open(fresh()?, limits())?;
    let mut second = Fixture::playing(&mut q, 4096, 1)?; second.picture()?;
    let mut changed = timing(); changed.decode_time += 1;
    let _ = second.driver.supply_timing(changed, 12, &second.authority)?;
    second.driver.seal(13, &second.authority)?;
    let _ = second.driver.poll(SocketReadiness::default(), 13, &second.authority, &NeverCancel)?;
    let other = second.driver.cancel().ok_or("second retirement")?.archive.ok_or("second archive")?
        .pending.ok_or("second pending")?;
    assert_ne!(other.manifest().root(), admission.root); drop(second);
    publish_exact(&mut p, admission.slot.clone(), &other)?;
    let refusal = RecordingArchiveResume::open(&mut p, retired, config, 30, &NeverCancel)
        .err().ok_or("conflicting pending root adopted")?;
    assert!(matches!(refusal.reason, ArchiveError::Metadata));
    assert_eq!(refusal.retired.pending.as_ref().ok_or("lost original")?.manifest().root(), admission.root);
    assert_eq!(p.root(&admission.slot).ok_or("overwrote conflict")?.root, other.manifest().root()); Ok(())
}

#[test]
fn cancelled_resume_retains_unoffered_window_and_does_not_implicitly_retry() -> Test {
    struct Cancel;
    impl PublishCancellation for Cancel { fn cancel_requested(&self, _: PublishCutPoint) -> bool { true } }
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::playing(&mut p, 4096, 1)?; let admission = f.window()?;
    let retired = f.driver.cancel().ok_or("retirement")?.archive.ok_or("archive")?;
    let config = resume_config(&retired)?; drop(f);
    let mut resume = RecordingArchiveResume::open(&mut p, retired, config, 20, &NeverCancel)?;
    assert!(resume.step(21, &Cancel).is_err());
    assert!(matches!(resume.step(22, &NeverCancel), Err(ArchiveError::Blocked)));
    let retired = resume.retire().into_retry().map_err(|_| "lost retry ownership")?;
    assert_eq!(retired.pending.as_ref().ok_or("lost pending")?.manifest().root(), admission.root);
    assert_eq!(p.visible_roots().count(), 0); Ok(())
}

#[test]
fn retry_preserves_both_a_prepared_older_page_and_the_next_unoffered_window() -> Test {
    let path = fresh()?; let mut p = LocalRootPublisher::open(&path, limits())?;
    let mut f = Fixture::playing(&mut p, 4096, 4)?;
    let first = f.window()?; f.storage(14)?;
    let data = nals(); let idr = data.iter().find(|n| n[0] & 31 == 5).ok_or("missing IDR")?;
    let mut next = wire(3, true, idr)?;
    next[8..12].copy_from_slice(&12_600_u32.to_be_bytes());
    let _ = f.receive(&next, 15)?;
    let mut later = timing(); later.decode_time += u64::from(later.duration);
    let _ = f.driver.supply_timing(later, 16, &f.authority)?;
    assert!(f.driver.seal(17, &f.authority)?);
    let LiveArchiveStep::WindowAccepted(second) = f.driver.poll(SocketReadiness::default(), 17, &f.authority, &NeverCancel)?
        else { return Err("second window was not admitted".into()); };
    assert_ne!(first.root, second.root);
    let retired = f.driver.cancel().ok_or("retirement")?.archive.ok_or("archive")?;
    assert_eq!(retired.snapshot.windows().len(), 1);
    let config = resume_config(&retired)?; drop(f); drop(p);
    let mut p = LocalRootPublisher::open(&path, limits())?;
    let mut resume = RecordingArchiveResume::open(&mut p, retired, config, 20, &NeverCancel)?;
    let mut expected = None;
    for _ in 0..128 {
        if let ArchiveResumeProgress::Archive(ArchiveWriteProgress::CatalogPrepared { root }) = resume.step(21, &NeverCancel)? {
            expected = Some(root); break;
        }
    }
    let expected = expected.ok_or("original tail page was not prepared")?;
    let retired = resume.retire().into_retry().map_err(|_| "lost split ownership")?;
    assert_eq!(retired.prepared_page.as_ref().ok_or("lost old page")?.manifest().root(), expected);
    assert_eq!(retired.pending.as_ref().ok_or("lost next window")?.manifest().root(), second.root);
    let config = resume_config(&retired)?; drop(p);
    let mut p = LocalRootPublisher::open(&path, limits())?;
    let mut resume = RecordingArchiveResume::open(&mut p, retired, config, 30, &NeverCancel)?;
    assert_eq!(resume.reconciliation().page, RetiredPublicationState::NotPublished(expected));
    assert_eq!(resume.reconciliation().window, RetiredPublicationState::NotPublished(second.root));
    complete(&mut resume, 31)?;
    assert_eq!(resume.snapshot().windows().len(), 2); assert_eq!(resume.snapshot().indexed_windows(), 2);
    assert_eq!(resume.snapshot().pages().len(), 2);
    assert_eq!(resume.snapshot().pages()[0].catalog().manifest().root(), expected);
    assert_eq!(resume.snapshot().windows()[1].root(), second.root);
    Ok(())
}

#[test]
fn protocol_failure_preserves_durable_unindexed_tail_and_never_emits_finished() -> Test {
    let mut p = LocalRootPublisher::open(fresh()?, limits())?;
    let mut f = Fixture::playing(&mut p, 4096, 4)?; let admission = f.window()?; f.storage(14)?;
    f.peer.write_all(b"RTSP/1.0 200 OK\r\nCSeq: ")?;
    f.peer.shutdown(Shutdown::Write)?;
    for _ in 0..128 {
        match f.driver.poll(SocketReadiness { readable: true, writable: false }, 15, &f.authority, &NeverCancel)? {
            LiveArchiveStep::Stopped { retained, .. } => {
                let archive = retained.archive.ok_or("lost unindexed archive")?;
                assert_eq!(archive.snapshot.windows().len(), 1);
                assert_eq!(archive.snapshot.windows()[0].root(), admission.root);
                assert_eq!(archive.snapshot.indexed_windows(), 0);
                return Ok(());
            }
            LiveArchiveStep::Finished { .. } => return Err("protocol failure was fabricated into EOF completion".into()),
            _ => {},
        }
    }
    Err("truncated protocol did not stop the archive".into())
}

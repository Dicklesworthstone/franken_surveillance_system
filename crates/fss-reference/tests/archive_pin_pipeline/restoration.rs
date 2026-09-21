#![forbid(unsafe_code)]
//! Cold restoration through the independent journal and original root-last publisher.
use super::*;
use fss_publication::PublishOutcome;
use fss_reference::rtsp::recording_archive::checkpoint::write_ahead::{
    CheckpointedArchiveProgress, CheckpointedArchiveWriter};

fn candidate(p: &mut LocalRootPublisher, pins: &mut ArchivePinJournal, durable: bool) -> Test<ContentDigest> {
    let mut w = CheckpointedArchiveWriter::open(p, namespace()?, limits(), ArchiveWorkLimits::default(),
        256, 0, 1000, &NeverCancel)?;
    let window = window(0)?; let root = window.manifest().root(); let bytes = window.byte_len();
    w.offer(window, bytes, 0)?;
    let CheckpointedArchiveProgress::PinRequired(pin) = w.step(0, &NeverCancel)? else { return Err("pin missing".into()); };
    pins.persist_candidate(&pin, &NeverCancel)?;
    if durable {
        w.acknowledge_checkpoint(&pin, 0, &NeverCancel)?;
        assert!(matches!(w.step(0, &NeverCancel)?, CheckpointedArchiveProgress::WorkDurable { .. }));
    }
    let _retired = w.retire();
    Ok(root)
}
fn reopen(path: &Path) -> Test<(LocalRootPublisher, ArchivePinJournal)> {
    Ok((LocalRootPublisher::open(path.join("media"), storage())?,
        ArchivePinJournal::open_existing(path.join("pins"), pin_scope()?, None,
            ArchivePinLimits::default(), IncompleteTailPolicy::Reject, &NeverCancel)?))
}
#[test]
fn candidate_work_restores_after_every_original_object_and_receipt_is_lost() -> Test {
    let path = fresh("restore_candidate")?;
    let root = {
        let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
        let mut pins = ArchivePinJournal::create(path.join("pins"), pin_scope()?, ArchivePinLimits::default(), &NeverCancel)?;
        candidate(&mut p, &mut pins, true)?
    };
    let (mut p, mut pins) = reopen(&path)?;
    let result = pins.restore_work(&mut p, ArchiveWorkLimits::default(), 0, 1000, &NeverCancel)?;
    assert_eq!(result.window.as_ref().ok_or("window receipt")?.root, root);
    assert!(result.confirmation.is_some()); assert!(result.catalog.is_none());
    assert_eq!((result.durable_windows,result.indexed_windows,result.pages), (1,0,0));
    assert_eq!(result.journal_anchor.sequence,3);
    assert!(pins.state().candidate().is_none());
    pins.require_settled(&p, ArchiveWorkLimits::default(), &NeverCancel)?;
    // No ordinary catalog is invented. A fresh protected writer can now index the recovered tail.
    let mut w = writer(&mut p, &mut pins)?;
    assert_eq!(finish(&mut w)?, (1,1));
    Ok(())
}
#[test]
fn lost_restoration_response_is_an_exact_retry_without_new_journal_or_archive_roots() -> Test {
    let path = fresh("restore_lost_reply")?;
    let anchor = {
        let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
        let mut pins = ArchivePinJournal::create(path.join("pins"), pin_scope()?, ArchivePinLimits::default(), &NeverCancel)?;
        candidate(&mut p, &mut pins, true)?;
        let _lost_reply = pins.restore_work(&mut p, ArchiveWorkLimits::default(), 0, 1000, &NeverCancel)?;
        pins.anchor()
    };
    let (mut p, mut pins) = reopen(&path)?; let count = p.visible_roots().count();
    let result = pins.restore_work(&mut p, ArchiveWorkLimits::default(), 0, 1000, &NeverCancel)?;
    assert_eq!(result.window.as_ref().ok_or("window receipt")?.outcome, PublishOutcome::AlreadyPublished);
    assert!(result.confirmation.is_none()); assert_eq!(pins.anchor(),anchor);
    assert_eq!(p.visible_roots().count(),count);
    Ok(())
}
#[test]
fn uncertain_normal_window_commit_keeps_same_journal_selection_for_reopen() -> Test {
    let path = fresh("restore_uncertain")?;
    {
        let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
        let mut pins = ArchivePinJournal::create(path.join("pins"), pin_scope()?, ArchivePinLimits::default(), &NeverCancel)?;
        candidate(&mut p, &mut pins, true)?;
        p.inject_crash_at(PublishCutPoint::AfterRootRename);
        assert!(pins.restore_work(&mut p, ArchiveWorkLimits::default(), 0, 1000, &NeverCancel).is_err());
        assert_eq!(pins.anchor().sequence,3);
    }
    let (mut p, mut pins) = reopen(&path)?;
    let result = pins.restore_work(&mut p, ArchiveWorkLimits::default(), 0, 1000, &NeverCancel)?;
    assert_eq!(result.window.as_ref().ok_or("window receipt")?.outcome, PublishOutcome::AlreadyPublished);
    assert_eq!(result.durable_windows,1); assert_eq!(pins.anchor().sequence,3);
    Ok(())
}
#[test]
fn uncommitted_candidate_is_not_discarded_or_reported_as_success() -> Test {
    let path = fresh("restore_missing")?;
    let mut p = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = ArchivePinJournal::create(path.join("pins"), pin_scope()?, ArchivePinLimits::default(), &NeverCancel)?;
    candidate(&mut p,&mut pins,false)?; let anchor=pins.anchor();
    assert!(pins.restore_work(&mut p, ArchiveWorkLimits::default(), 0, 1000, &NeverCancel).is_err());
    assert_eq!(pins.anchor(),anchor); assert!(pins.state().candidate().is_some());
    assert_eq!(p.visible_roots().count(),0);
    Ok(())
}
#[test]
fn confirmation_capacity_failure_precedes_any_normal_publication() -> Test {
    let path=fresh("restore_confirm_budget")?;
    let mut p=LocalRootPublisher::open(path.join("media"),storage())?;
    let mut pins=ArchivePinJournal::create(path.join("pins"),pin_scope()?,
        ArchivePinLimits {max_records:2,..ArchivePinLimits::default()},&NeverCancel)?;
    candidate(&mut p,&mut pins,true)?; let count=p.visible_roots().count();
    assert!(matches!(pins.restore_work(&mut p,ArchiveWorkLimits::default(),0,1000,&NeverCancel),Err(ArchivePinError::Limit)));
    assert_eq!(p.visible_roots().count(),count); assert!(p.root(&namespace()?.window_slot(0)?).is_none());
    assert!(pins.state().candidate().is_some());
    Ok(())
}
#[test]
fn cancellation_and_expired_admission_do_not_confirm_or_restore() -> Test {
    struct Cancel;
    impl PublishCancellation for Cancel {fn cancel_requested(&self,_:PublishCutPoint)->bool{true}}
    let path=fresh("restore_cancel")?;
    let mut p=LocalRootPublisher::open(path.join("media"),storage())?;
    let mut pins=ArchivePinJournal::create(path.join("pins"),pin_scope()?,ArchivePinLimits::default(),&NeverCancel)?;
    candidate(&mut p,&mut pins,true)?; let anchor=pins.anchor(); let count=p.visible_roots().count();
    assert!(matches!(pins.restore_work(&mut p,ArchiveWorkLimits::default(),0,1000,&Cancel),Err(ArchivePinError::Cancelled)));
    assert!(pins.restore_work(&mut p,ArchiveWorkLimits::default(),1000,1000,&NeverCancel).is_err());
    assert_eq!(pins.anchor(),anchor); assert_eq!(p.visible_roots().count(),count);
    Ok(())
}
#[test]
fn original_catalog_restores_without_constructing_a_different_page() -> Test {
    let path=fresh("restore_catalog")?;
    let expected={
        let mut p=LocalRootPublisher::open(path.join("media"),storage())?;
        let mut pins=ArchivePinJournal::create(path.join("pins"),pin_scope()?,ArchivePinLimits::default(),&NeverCancel)?;
        let mut w=writer(&mut p,&mut pins)?; offer(&mut w)?;
        for _ in 0..3 {let _=w.step(0,&NeverCancel)?;}
        w.flush(0)?;
        let mut page=None;
        for _ in 0..16 {
            if let JournaledArchiveProgress::WorkConfirmed {checkpoint,..}=w.step(0,&NeverCancel)? {
                page=Some(checkpoint.root()); break;
            }
        }
        let retired=w.retire(); assert!(retired.writer.archive.prepared_page.is_some());
        (page.ok_or("checkpoint not reached")?, retired.writer.archive.prepared_page.ok_or("page missing")?.manifest().root())
    };
    let (mut p,mut pins)=reopen(&path)?;
    let result=pins.restore_work(&mut p,ArchiveWorkLimits::default(),0,1000,&NeverCancel)?;
    assert_eq!(result.pin.root(),expected.0);
    assert_eq!(result.catalog.as_ref().ok_or("catalog receipt")?.root,expected.1);
    assert!(result.window.is_none()); assert_eq!((result.durable_windows,result.indexed_windows,result.pages),(1,1,1));
    Ok(())
}
#[test]
fn source_corruption_is_not_a_license_to_confirm_a_candidate() -> Test {
    let path=fresh("restore_corrupt")?;
    let mut p=LocalRootPublisher::open(path.join("media"),storage())?;
    let mut pins=ArchivePinJournal::create(path.join("pins"),pin_scope()?,ArchivePinLimits::default(),&NeverCancel)?;
    candidate(&mut p,&mut pins,true)?;
    let source=window(0)?.children()[0].1.to_text();
    let file=path.join("media/spool/objects").join(source.strip_prefix("sha256:").ok_or("digest")?);
    let mut bytes=std::fs::read(&file)?;
    *bytes.last_mut().ok_or("empty source")?^=1; std::fs::write(file,bytes)?;
    let anchor=pins.anchor();
    assert!(pins.restore_work(&mut p,ArchiveWorkLimits::default(),0,1000,&NeverCancel).is_err());
    assert_eq!(pins.anchor(),anchor); assert!(pins.state().candidate().is_some());
    assert!(p.root(&namespace()?.window_slot(0)?).is_none());
    Ok(())
}

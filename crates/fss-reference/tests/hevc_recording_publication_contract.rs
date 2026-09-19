#![forbid(unsafe_code)]
//! HEVC root-last storage, crash/reopen and full-replay readback contracts.
mod hevc_recording_support;
mod recording_support;
use hevc_recording_support::*;
use fss_core::{CanonicalEncoder, ContentDigest};
use fss_object::{ObjectManifest, SpoolLimits};
use fss_publication::{LocalPublicationLimits, LocalPublicationState, LocalRootPublisher,
    NeverCancel, PublishCancellation, PublishCutPoint, PublishOutcome, SlotName};
use fss_reference::rtsp::recording::{PreparedRecording, RecordingError, RecordingRole};
use fss_reference::rtsp::recording::local::{
    RecordingIoError as E, RecordingProgress, RecordingPublication, load_recording,
};
use fss_reference::rtsp::recording::hevc::{HEVC_RECORDING_KIND, PreparedHevcRecording};
use fss_reference::rtsp::recording::hevc::local::load_hevc_recording;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
type TestResult = Result<(), Error>;

fn fresh(name: &str) -> Result<PathBuf, Error> {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("hevc_recording_publication_contract").join(name);
    match std::fs::remove_dir_all(&path) {
        Ok(()) => {}, Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
        Err(e) => return Err(e.into()),
    }
    Ok(path)
}
fn limits() -> LocalPublicationLimits {
    LocalPublicationLimits::new(8, 16, 8, 64,
        SpoolLimits::new(64, 4 * 1024 * 1024, 1024 * 1024, 64))
}
fn slot() -> Result<SlotName, Error> { Ok(SlotName::parse("hevc-recording-001")?) }
fn publish(plan: &PreparedRecording, publisher: &mut LocalRootPublisher, slot: SlotName)
    -> Result<PublishOutcome, Error>
{
    let mut job = RecordingPublication::new(plan, publisher, slot, plan.byte_len(), 100)?;
    for now in 0..5 {
        if let RecordingProgress::Published(receipt) = job.step(now, &NeverCancel)? {
            assert_eq!(receipt.root, plan.manifest().root());
            assert_eq!(receipt.claims.local, LocalPublicationState::Durable);
            return Ok(receipt.outcome);
        }
    }
    Err("no durable receipt after four children and one root step".into())
}
fn stage(plan: &PreparedRecording, publisher: &mut LocalRootPublisher) -> TestResult {
    let mut job = RecordingPublication::new(plan, publisher, slot()?, plan.byte_len(), 100)?;
    for now in 0..4 { assert!(matches!(job.step(now, &NeverCancel)?, RecordingProgress::ChildStaged { .. })); }
    Ok(())
}
struct CancelAt(PublishCutPoint);
impl PublishCancellation for CancelAt {
    fn cancel_requested(&self, point: PublishCutPoint) -> bool { point == self.0 }
}
struct CancelReadAt { calls: AtomicUsize, at: usize }
impl PublishCancellation for CancelReadAt {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.calls.fetch_add(1, Ordering::SeqCst) >= self.at
    }
}

#[test]
fn unchanged_publisher_stages_source_first_and_never_serves_unpublished_hevc() -> TestResult {
    let plan = fixture()?; let content = plan.publication_plan();
    let mut owner = LocalRootPublisher::open(fresh("source_first")?, limits())?;
    {
        let mut job = RecordingPublication::new(content, &mut owner, slot()?, plan.byte_len(), 100)?;
        for (now, expected) in [RecordingRole::Source, RecordingRole::Initialization,
            RecordingRole::Media, RecordingRole::Index].into_iter().enumerate() {
            assert!(matches!(job.step(now as u64, &NeverCancel)?, RecordingProgress::ChildStaged { role, remaining, .. }
                if role == expected && remaining == 3 - now));
        }
    }
    assert!(owner.root(&slot()?).is_none());
    assert_eq!(owner.spool().read(content.children()[0].1)?, plan.objects().source);
    assert!(matches!(load_hevc_recording(&owner, &slot()?, plan.manifest().root(), &scope()?, &NeverCancel), Err(E::NotDurable)));
    assert_eq!(publish(content, &mut owner, slot()?)?, PublishOutcome::Published);
    load_hevc_recording(&owner, &slot()?, plan.manifest().root(), &scope()?, &NeverCancel)?;
    Ok(())
}

#[test]
fn process_reopen_replays_and_preserves_all_bytes_maps_and_source_only_witnesses() -> TestResult {
    let originals = packets()?;
    let plan = prepare(&originals[..8], &timings(2))?;
    let path = fresh("reopen")?;
    {
        let mut owner = LocalRootPublisher::open(&path, limits())?;
        publish(plan.publication_plan(), &mut owner, slot()?)?;
    }
    let owner = LocalRootPublisher::open(&path, limits())?;
    let read = load_hevc_recording(&owner, &slot()?, plan.manifest().root(), &scope()?, &NeverCancel)?;
    assert_eq!(read.manifest(), plan.manifest()); assert_eq!(read.summary(), plan.summary());
    assert_eq!(read.source_only_nals(), 3);
    assert_eq!(read.objects().source, plan.objects().source);
    assert_eq!(read.objects().initialization, plan.objects().initialization);
    assert_eq!(read.objects().media, plan.objects().media);
    assert_eq!(read.objects().index, plan.objects().index);
    assert_eq!(read.samples(), plan.samples()); assert_eq!(read.mappings(), plan.mappings());
    for (a, b) in read.packets()?.iter().zip(&originals[..8]) {
        assert_eq!(a.sequence, b.sequence); assert_eq!(a.received_ns, b.received_ns); assert_eq!(a.bytes, b.bytes);
    }
    Ok(())
}

#[test]
fn every_child_crash_prefix_remains_unpublished_and_can_resume_with_exact_bytes() -> TestResult {
    let plan = fixture()?;
    for cut in 0..=4 {
        let path = fresh(&format!("child_cut_{cut}"))?;
        {
            let mut owner = LocalRootPublisher::open(&path, limits())?;
            let mut job = RecordingPublication::new(plan.publication_plan(), &mut owner, slot()?, plan.byte_len(), 100)?;
            for now in 0..cut { job.step(now, &NeverCancel)?; }
        }
        let mut owner = LocalRootPublisher::open(&path, limits())?;
        assert!(owner.root(&slot()?).is_none());
        assert!(matches!(load_hevc_recording(&owner, &slot()?, plan.manifest().root(), &scope()?, &NeverCancel), Err(E::NotDurable)));
        assert_eq!(publish(plan.publication_plan(), &mut owner, slot()?)?, PublishOutcome::Published);
        let read = load_hevc_recording(&owner, &slot()?, plan.manifest().root(), &scope()?, &NeverCancel)?;
        assert_eq!(read.objects().source, plan.objects().source);
    }
    Ok(())
}

#[test]
fn root_crash_cut_points_preserve_staged_visible_durable_and_repair_distinctions() -> TestResult {
    let plan = fixture()?;
    for (n, cut) in [PublishCutPoint::AfterChildrenVerified, PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite, PublishCutPoint::AfterRootRename].into_iter().enumerate() {
        let path = fresh(&format!("root_cut_{n}"))?;
        {
            let mut owner = LocalRootPublisher::open(&path, limits())?;
            stage(plan.publication_plan(), &mut owner)?;
            owner.inject_crash_at(cut);
            {
                let mut job = RecordingPublication::new(plan.publication_plan(), &mut owner, slot()?, plan.byte_len(), 100)?;
                for now in 0..4 { job.step(now, &NeverCancel)?; }
                assert!(job.step(4, &NeverCancel).is_err());
            }
            assert!(matches!(load_hevc_recording(&owner, &slot()?, plan.manifest().root(), &scope()?, &NeverCancel), Err(E::ReopenRequired)));
        }
        let mut owner = LocalRootPublisher::open(&path, limits())?;
        match cut {
            PublishCutPoint::AfterRootRename => {
                assert_eq!(publish(plan.publication_plan(), &mut owner, slot()?)?, PublishOutcome::AlreadyPublished);
                load_hevc_recording(&owner, &slot()?, plan.manifest().root(), &scope()?, &NeverCancel)?;
            }
            PublishCutPoint::AfterRootTempWrite => {
                assert!(owner.root(&slot()?).is_none());
                assert!(!owner.recovery_report().orphaned_temps.is_empty());
                assert!(publish(plan.publication_plan(), &mut owner, slot()?).is_err());
                // No implicit orphan deletion to turn an unresolved write into success.
                assert!(!owner.recovery_report().orphaned_temps.is_empty());
            }
            _ => {
                assert!(owner.root(&slot()?).is_none());
                assert_eq!(publish(plan.publication_plan(), &mut owner, slot()?)?, PublishOutcome::Published);
            }
        }
    }
    Ok(())
}

#[test]
fn a_lost_final_receipt_reconciles_without_replacing_or_republishing_a_different_root() -> TestResult {
    let plan = fixture()?; let path = fresh("lost_receipt")?;
    { let mut owner = LocalRootPublisher::open(&path, limits())?; publish(plan.publication_plan(), &mut owner, slot()?)?; }
    let mut owner = LocalRootPublisher::open(&path, limits())?;
    assert_eq!(publish(plan.publication_plan(), &mut owner, slot()?)?, PublishOutcome::AlreadyPublished);
    assert_eq!(owner.visible_roots().count(), 1);
    let loaded = load_hevc_recording(&owner, &slot()?, plan.manifest().root(), &scope()?, &NeverCancel)?;
    assert_eq!(publish(loaded.publication_plan(), &mut owner, slot()?)?, PublishOutcome::AlreadyPublished);
    Ok(())
}

#[test]
fn cancellation_and_root_temp_cancellation_preserve_source_without_claiming_a_root() -> TestResult {
    let plan = fixture()?;
    for at_root in [false, true] {
        let mut owner = LocalRootPublisher::open(fresh(if at_root { "cancel_root" } else { "cancel_child" })?, limits())?;
        {
            let mut job = RecordingPublication::new(plan.publication_plan(), &mut owner, slot()?, plan.byte_len(), 100)?;
            job.step(0, &NeverCancel)?;
            if at_root {
                for now in 1..4 { job.step(now, &NeverCancel)?; }
                assert!(job.step(4, &CancelAt(PublishCutPoint::AfterRootTempWrite)).is_err());
            } else {
                assert!(matches!(job.step(1, &CancelAt(PublishCutPoint::AfterChildrenVerified)), Err(E::Cancelled)));
            }
            assert!(matches!(job.step(5, &NeverCancel), Err(E::Stopped)));
        }
        assert!(owner.root(&slot()?).is_none());
        assert_eq!(owner.spool().read(plan.publication_plan().children()[0].1)?, plan.objects().source);
        assert!(load_hevc_recording(&owner, &slot()?, plan.manifest().root(), &scope()?, &NeverCancel).is_err());
    }
    Ok(())
}

#[test]
fn cancellation_at_each_read_or_after_full_replay_prevents_disclosure_not_durability() -> TestResult {
    let plan = fixture()?;
    let mut owner = LocalRootPublisher::open(fresh("cancel_read")?, limits())?;
    publish(plan.publication_plan(), &mut owner, slot()?)?;
    // Five exact objects (manifest/index/source/init/media), then the final
    // post-verification cancellation check. No successful bytes escape any cut.
    for at in 0..6 {
        let cancel = CancelReadAt { calls: AtomicUsize::new(0), at };
        assert!(matches!(load_hevc_recording(&owner, &slot()?, plan.manifest().root(), &scope()?, &cancel), Err(E::Cancelled)));
        assert_eq!(cancel.calls.load(Ordering::SeqCst), at + 1);
        assert_eq!(owner.root(&slot()?).ok_or("root was retracted")?.state, LocalPublicationState::Durable);
    }
    load_hevc_recording(&owner, &slot()?, plan.manifest().root(), &scope()?, &NeverCancel)?;
    Ok(())
}

#[test]
fn wrong_root_scope_and_conflicting_recording_never_overwrite_the_existing_slot() -> TestResult {
    let plan = fixture()?;
    let mut owner = LocalRootPublisher::open(fresh("conflict")?, limits())?;
    publish(plan.publication_plan(), &mut owner, slot()?)?;
    assert!(matches!(load_hevc_recording(&owner, &slot()?, ContentDigest::sha256(b"wrong-root"), &scope()?, &NeverCancel), Err(E::RootConflict)));
    let mut other_scope = scope()?; other_scope.generation += 1;
    assert!(matches!(load_hevc_recording(&owner, &slot()?, plan.manifest().root(), &other_scope, &NeverCancel), Err(E::Content(RecordingError::Scope))));
    let mut source = packets()?; source[0].received_ns += 1;
    let other = prepare(&source, &timings(4))?;
    assert!(matches!(RecordingPublication::new(other.publication_plan(), &mut owner, slot()?, other.byte_len(), 100), Err(E::RootConflict)));
    assert_eq!(owner.root(&slot()?).ok_or("lost root")?.root, plan.manifest().root());
    Ok(())
}

#[test]
fn corrupt_source_init_media_or_index_is_never_returned_as_a_verified_recording() -> TestResult {
    let plan = fixture()?;
    for role in 0..4 {
        let path = fresh(&format!("corrupt_role_{role}"))?;
        let mut owner = LocalRootPublisher::open(&path, limits())?;
        publish(plan.publication_plan(), &mut owner, slot()?)?;
        let digest = plan.publication_plan().children()[role].1.to_text();
        let hex = digest.strip_prefix("sha256:").ok_or("not SHA-256")?;
        let object = path.join("spool").join("objects").join(hex);
        let mut bytes = std::fs::read(&object)?;
        *bytes.last_mut().ok_or("empty fixture object")? ^= 1;
        std::fs::write(&object, bytes)?;
        assert!(load_hevc_recording(&owner, &slot()?, plan.manifest().root(), &scope()?, &NeverCancel).is_err());
        drop(owner);
        let reopened = LocalRootPublisher::open(&path, limits())?;
        assert!(load_hevc_recording(&reopened, &slot()?, plan.manifest().root(), &scope()?, &NeverCancel).is_err());
        assert!(reopened.root(&slot()?).is_none());
    }
    Ok(())
}

#[test]
fn limits_deadlines_clock_reversal_and_completed_job_semantics_are_unchanged() -> TestResult {
    let plan = fixture()?;
    let mut owner = LocalRootPublisher::open(fresh("budget_clock")?, limits())?;
    assert!(matches!(RecordingPublication::new(plan.publication_plan(), &mut owner, slot()?, plan.byte_len() - 1, 100), Err(E::Budget)));
    {
        let mut job = RecordingPublication::new(plan.publication_plan(), &mut owner, slot()?, plan.byte_len(), 100)?;
        assert!(matches!(job.step(100, &NeverCancel), Err(E::Deadline)));
        assert!(matches!(job.step(99, &NeverCancel), Err(E::Stopped)));
    }
    let mut job = RecordingPublication::new(plan.publication_plan(), &mut owner, slot()?, plan.byte_len(), 100)?;
    job.step(10, &NeverCancel)?;
    assert!(matches!(job.step(9, &NeverCancel), Err(E::ClockReversed)));
    assert!(matches!(job.step(10, &NeverCancel)?, RecordingProgress::ChildStaged { role: RecordingRole::Initialization, .. }));
    for now in 11..14 { job.step(now, &NeverCancel)?; }
    assert_eq!(job.step(200, &CancelAt(PublishCutPoint::AfterChildrenVerified))?, RecordingProgress::Complete);
    Ok(())
}

#[test]
fn shared_readback_preserves_avc_and_never_chooses_a_codec_from_untrusted_metadata() -> TestResult {
    let hevc = fixture()?;
    let avc = recording_support::fixture(1, false)?.prepare()?;
    let avc_slot = SlotName::parse("avc-recording-001")?;
    let mut owner = LocalRootPublisher::open(fresh("codec_separation")?, limits())?;
    publish(hevc.publication_plan(), &mut owner, slot()?)?;
    publish(&avc, &mut owner, avc_slot.clone())?;
    assert!(load_recording(&owner, &slot()?, hevc.manifest().root(), &scope()?, &NeverCancel).is_err());
    assert!(load_hevc_recording(&owner, &avc_slot, avc.manifest().root(), &recording_support::scope()?, &NeverCancel).is_err());
    let loaded = load_recording(&owner, &avc_slot, avc.manifest().root(), &recording_support::scope()?, &NeverCancel)?;
    assert_eq!(loaded.objects().index, avc.objects().index);
    assert_eq!(loaded.objects().media, avc.objects().media);
    assert_eq!(loaded.summary(), avc.summary());
    let cancel = CancelReadAt { calls: AtomicUsize::new(0), at: 5 };
    assert!(matches!(load_recording(&owner, &avc_slot, avc.manifest().root(), &recording_support::scope()?, &cancel), Err(E::Cancelled)));
    Ok(())
}

fn range(e: &mut CanonicalEncoder, r: &std::ops::Range<usize>) { e.u64(r.start as u64); e.u64(r.end as u64); }
fn forged_boundary_index(plan: &PreparedHevcRecording) -> Result<Vec<u8>, Error> {
    use fss_packet::hevc::HevcBoundary;
    let mut e = CanonicalEncoder::new(); let s = &plan.summary().scope; let b = plan.objects();
    e.text("fss.hevc_recording_window.index.v1"); e.text(s.sensor.as_str()); e.text(s.stream.as_str());
    e.u64(s.generation); e.digest(s.anchor); e.digest(s.receive_clock);
    e.u32(SSRC); e.u32(u32::from(PT)); e.u32(plan.summary().time_scale);
    e.digest(ContentDigest::sha256(b.source)); e.digest(ContentDigest::sha256(b.initialization)); e.digest(ContentDigest::sha256(b.media));
    for r in plan.parameter_ranges() { range(&mut e, r); }
    e.u64(plan.source_only_nals() as u64); e.u64(plan.samples().len() as u64);
    for (i, sample) in plan.samples().iter().enumerate() {
        range(&mut e, &sample.range); e.u64(sample.decode_time); e.u64(sample.presentation_time);
        e.u32(sample.duration); e.u32(sample.rtp_timestamp); e.bool(sample.idr);
        let tag = match sample.boundary { HevcBoundary::NextFirstSlice => 1,
            HevcBoundary::NextAccessUnitPrefix => 2, HevcBoundary::AccessUnitDelimiter => 3,
            HevcBoundary::EndOfSequence => 4, HevcBoundary::EndOfBitstream => 5,
            HevcBoundary::EndOfInputUnverified => 6 };
        e.u64(if i == 0 { 4 } else { tag }); // Forge EOS for the real next-first-slice boundary.
        range(&mut e, &sample.mappings);
    }
    e.u64(plan.mappings().len() as u64);
    for m in plan.mappings() {
        e.u64(m.sample as u64); e.u64(m.nal as u64); range(&mut e, &m.range); e.u64(m.sources.len() as u64);
        for span in &m.sources {
            e.u64(span.sequence); range(&mut e, &span.wire_range); range(&mut e, &span.nal_range);
            e.bool(span.fragment_header_range.is_some());
            if let Some(r) = &span.fragment_header_range { range(&mut e, r); }
        }
    }
    Ok(e.finish_checked()?)
}

#[test]
fn even_a_durable_rehashed_forged_index_must_pass_native_source_replay_on_readback() -> TestResult {
    let plan = fixture()?; let bytes = plan.objects();
    let fake_index = forged_boundary_index(&plan)?;
    let forged = ObjectManifest::new(HEVC_RECORDING_KIND, [ContentDigest::sha256(bytes.source),
        ContentDigest::sha256(bytes.initialization), ContentDigest::sha256(bytes.media)],
        Some(ContentDigest::sha256(&fake_index)))?;
    assert_ne!(forged.root(), plan.manifest().root());
    let path = fresh("rehashed_forgery")?;
    {
        let mut owner = LocalRootPublisher::open(&path, limits())?;
        // The generic publisher verifies byte custody, not HEVC semantics.
        for object in [bytes.source, bytes.initialization, bytes.media, fake_index.as_slice()] { owner.stage_object(object)?; }
        let receipt = owner.publish(&slot()?, &forged)?;
        assert_eq!(receipt.claims.local, LocalPublicationState::Durable);
    }
    let owner = LocalRootPublisher::open(&path, limits())?;
    assert_eq!(owner.root(&slot()?).ok_or("forged root not durable")?.state, LocalPublicationState::Durable);
    assert!(matches!(load_hevc_recording(&owner, &slot()?, forged.root(), &scope()?, &NeverCancel), Err(E::Content(RecordingError::Source))));
    Ok(())
}

#![forbid(unsafe_code)]
//! Native HEVC source custody through independent pin synchronization and cold restoration.

mod hevc_archive_support;
mod hevc_catalog_support;
mod hevc_recording_support;

use fss_codec_h265::{Decoder, DecoderLimits};
use fss_container::demux::{AvcMp4, DemuxLimits, VideoCodec};
use fss_core::{CanonicalEncoder, ContentDigest};
use fss_ledger::recover_bytes;
use fss_object::SpoolLimits;
use fss_publication::{
    LocalPublicationLimits, LocalPublicationState, LocalRootPublisher, NeverCancel,
    PublishCutPoint, PublishOutcome, SlotName,
};
use fss_reference::rtsp::archive_pins::*;
use fss_reference::rtsp::recording::hevc::{PreparedHevcRecording, local::load_hevc_recording};
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording_archive::checkpoint::write_ahead::{
    ArchiveCheckpoint, CheckpointedArchiveProgress, CheckpointedHevcArchiveWriter,
};
use fss_reference::rtsp::recording_archive::checkpoint::{
    ArchiveWorkLimits, HEVC_ARCHIVE_WORK_KIND, PreparedHevcArchiveWork,
    hevc_archive_retirement_digest, load_archive_work, load_hevc_archive_work,
};
use fss_reference::rtsp::recording_archive::hevc::{
    HevcArchiveRead, HevcArchiveReadProgress, HevcArchiveSnapshot, HevcRecordingArchiveWriter,
};
use fss_reference::rtsp::recording_archive::{
    ArchiveError, ArchiveQueryLimits, ArchiveWriteProgress,
};
use hevc_archive_support::{archive_limits, corrupt, fresh, namespace};
use hevc_catalog_support as fixture;
use hevc_recording_support as source;
use std::path::Path;

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn storage() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        128,
        1024,
        128,
        1024,
        SpoolLimits::new(1024, 64 * 1024 * 1024, 1024 * 1024, 1024),
    )
}

fn scope() -> Test<ArchivePinScope> {
    Ok(ArchivePinScope {
        journal_id: ContentDigest::sha256(b"independent HEVC recovery epoch"),
        archive_namespace: namespace()?.digest(),
    })
}

fn create(path: &Path, limits: ArchivePinLimits) -> Test<HevcArchivePinJournal> {
    Ok(HevcArchivePinJournal::create(
        path.join("pins"),
        scope()?,
        limits,
        &NeverCancel,
    )?)
}

fn reopen(
    path: &Path,
    minimum: Option<ArchivePinAnchor>,
) -> Test<(LocalRootPublisher, HevcArchivePinJournal)> {
    Ok((
        LocalRootPublisher::open(path.join("media"), storage())?,
        HevcArchivePinJournal::open_complete(
            path.join("pins"),
            scope()?,
            minimum,
            ArchivePinLimits::default(),
            &NeverCancel,
        )?,
    ))
}

fn writer<'a, 'p>(
    publisher: &'a mut LocalRootPublisher,
    pins: &'p mut HevcArchivePinJournal,
) -> Test<JournaledHevcArchiveWriter<'a, 'p>> {
    Ok(JournaledHevcArchiveWriter::open(
        publisher,
        pins,
        namespace()?,
        archive_limits(),
        ArchiveWorkLimits::default(),
        256,
        0,
        1000,
        &NeverCancel,
    )?)
}

fn offer(writer: &mut JournaledHevcArchiveWriter<'_, '_>, at: u64) -> Test<ContentDigest> {
    let recording = fixture::window(at)?;
    let root = recording.manifest().root();
    let bytes = recording.byte_len();
    writer.offer(recording, bytes, 0)?;
    Ok(root)
}

fn finish(writer: &mut JournaledHevcArchiveWriter<'_, '_>) -> Test<(usize, usize)> {
    writer.finish(1)?;
    for _ in 0..128 {
        if let JournaledArchiveProgress::Archive(ArchiveWriteProgress::Finished {
            windows,
            pages,
            ..
        }) = writer.step(1, &NeverCancel)?
        {
            return Ok((windows, pages));
        }
    }
    Err("bounded HEVC pin/archive drain did not finish".into())
}

fn decode_pixels(recording: &PreparedHevcRecording) -> Test<usize> {
    let mut bytes = recording.objects().initialization.to_vec();
    bytes.extend_from_slice(recording.objects().media);
    let parsed = AvcMp4::parse(&bytes, None, DemuxLimits::default())?;
    assert_eq!(parsed.codec(), VideoCodec::Hevc);
    assert_eq!(parsed.samples().len(), recording.samples().len());
    let elementary = parsed.annex_b(0, parsed.samples().len())?;
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let mut pictures = decoder.decode_annex_b(elementary.bytes())?;
    pictures.extend(decoder.finish()?);
    assert!(pictures.iter().all(|p| {
        p.width() != 0
            && p.height() != 0
            && p.luma().len() == p.width() as usize * p.height() as usize
    }));
    Ok(pictures.len())
}

fn pin_candidate(
    publisher: &mut LocalRootPublisher,
    pins: &mut HevcArchivePinJournal,
    durable: bool,
) -> Test<ArchiveCheckpoint> {
    let mut writer = CheckpointedHevcArchiveWriter::open(
        publisher,
        namespace()?,
        archive_limits(),
        ArchiveWorkLimits::default(),
        256,
        0,
        1000,
        &NeverCancel,
    )?;
    let recording = fixture::window(0)?;
    let bytes = recording.byte_len();
    writer.offer(recording, bytes, 0)?;
    let CheckpointedArchiveProgress::PinRequired(pin) = writer.step(0, &NeverCancel)? else {
        return Err("missing HEVC candidate".into());
    };
    pins.persist_candidate(&pin, &NeverCancel)?;
    if durable {
        writer.acknowledge_checkpoint(&pin, 0, &NeverCancel)?;
        assert!(matches!(
            writer.step(0, &NeverCancel)?,
            CheckpointedArchiveProgress::WorkDurable { .. }
        ));
    }
    let _retired = writer.retire();
    Ok(pin)
}

#[test]
fn two_windows_retain_shared_boundary_witnesses_and_cold_decode_after_both_barriers() -> Test {
    let path = fresh("protected_hevc_two_windows")?;
    let originals = source::packets()?;
    let first = source::prepare(&originals[..6], &source::timings(2))?;
    let second = source::prepare(&originals[5..], &source::timings(4)[2..])?;
    assert_eq!(first.source_only_nals(), 1);
    assert_eq!(first.summary().samples, 2);
    assert_eq!(second.summary().samples, 2);
    let expected = [first, second];
    let (anchor, digest) = {
        let mut publisher = LocalRootPublisher::open(path.join("media"), storage())?;
        let mut pins = create(&path, ArchivePinLimits::default())?;
        let mut writer = writer(&mut publisher, &mut pins)?;
        for (ordinal, original) in expected.iter().enumerate() {
            // Reprepare a native fixture solely for admission; the expected copy never
            // participates in recovery, publication, or demux of the reopened recording.
            let recording = if ordinal == 0 {
                source::prepare(&originals[..6], &source::timings(2))?
            } else {
                source::prepare(&originals[5..], &source::timings(4)[2..])?
            };
            let bytes = recording.byte_len();
            let admission = writer.offer(recording, bytes, 0)?;
            assert_eq!(admission.ordinal, ordinal);
            assert_eq!(admission.root, original.manifest().root());
            assert!(matches!(
                writer.step(0, &NeverCancel)?,
                JournaledArchiveProgress::PinPersisted { checkpoint, receipt }
                    if checkpoint.slot().as_str().starts_with("fsshaw1-")
                        && receipt.phase() == ArchivePinPhase::Candidate
            ));
            assert_eq!(writer.snapshot().windows().len(), ordinal);
            assert!(matches!(
                writer.step(0, &NeverCancel)?,
                JournaledArchiveProgress::WorkConfirmed { work_receipt, pin_receipt, .. }
                    if work_receipt.claims.local == LocalPublicationState::Durable
                        && pin_receipt.phase() == ArchivePinPhase::Confirmed
            ));
            assert_eq!(writer.snapshot().windows().len(), ordinal);
            assert!(matches!(
                writer.step(0, &NeverCancel)?,
                JournaledArchiveProgress::Archive(ArchiveWriteProgress::WindowDurable { ordinal: got, .. })
                    if got == ordinal
            ));
        }
        assert_eq!(finish(&mut writer)?, (2, 1));
        assert_eq!(writer.snapshot().indexed_windows(), 2);
        assert_eq!(writer.journal_anchor().sequence, 7);
        assert!(writer.pin_state().candidate().is_none());
        let digest = writer.snapshot().digest()?;
        let retired = writer.retire();
        assert!(retired.writer.archive.pending.is_none());
        assert!(retired.writer.archive.prepared_page.is_none());
        assert!(retired.unrecorded_confirmation.is_none());
        pins.require_settled(&publisher, ArchiveWorkLimits::default(), &NeverCancel)?;
        (pins.anchor(), digest)
    };
    let (publisher, mut pins) = reopen(&path, Some(anchor))?;
    pins.require_settled(&publisher, ArchiveWorkLimits::default(), &NeverCancel)?;
    let snapshot =
        HevcArchiveSnapshot::load(&publisher, namespace()?, archive_limits(), &NeverCancel)?;
    assert_eq!(snapshot.digest()?, digest);
    let mut read = HevcArchiveRead::new(
        &publisher,
        &snapshot,
        0..72_000,
        ArchiveQueryLimits::default(),
        1000,
    )?;
    let mut decoded = 0;
    for (ordinal, expected) in expected.iter().enumerate() {
        let HevcArchiveReadProgress::Window {
            ordinal: got,
            recording,
            ..
        } = read.step(1, &NeverCancel)?
        else {
            return Err("missing cold HEVC window".into());
        };
        assert_eq!(got, ordinal);
        assert_eq!(recording.objects().source, expected.objects().source);
        assert_eq!(recording.objects().media, expected.objects().media);
        assert_eq!(recording.mappings(), expected.mappings());
        assert_eq!(recording.source_only_nals(), expected.source_only_nals());
        decoded += decode_pixels(&recording)?;
    }
    assert_eq!(decoded, 4);
    assert!(matches!(
        read.step(1, &NeverCancel)?,
        HevcArchiveReadProgress::Complete(_)
    ));
    // Shared source witness packet is preserved by each root, not promoted to a fifth sample.
    let first_packets = expected[0].packets()?;
    let second_packets = expected[1].packets()?;
    assert_eq!(
        first_packets.last().ok_or("first witness")?.bytes,
        second_packets[0].bytes
    );
    let journal = std::fs::read(path.join("pins/pins.journal"))?;
    for recording in &expected {
        assert!(
            !journal
                .windows(recording.objects().source.len())
                .any(|b| b == recording.objects().source)
        );
    }
    Ok(())
}

#[test]
fn lost_work_acknowledgement_restores_candidate_and_retries_original_slot_without_duplication()
-> Test {
    let path = fresh("protected_hevc_lost_work_ack")?;
    let (anchor, root, source_bytes) = {
        let mut publisher = LocalRootPublisher::open(path.join("media"), storage())?;
        let mut pins = create(&path, ArchivePinLimits::default())?;
        let mut writer = CheckpointedHevcArchiveWriter::open(
            &mut publisher,
            namespace()?,
            archive_limits(),
            ArchiveWorkLimits::default(),
            256,
            0,
            1000,
            &NeverCancel,
        )?;
        let recording = fixture::window(0)?;
        let root = recording.manifest().root();
        let source_bytes = recording.objects().source.to_vec();
        let bytes = recording.byte_len();
        writer.offer(recording, bytes, 0)?;
        let CheckpointedArchiveProgress::PinRequired(pin) = writer.step(0, &NeverCancel)? else {
            return Err("missing independently pinnable work".into());
        };
        pins.persist_candidate(&pin, &NeverCancel)?;
        let anchor = pins.anchor();
        let retired = writer.retire();
        let window = retired.archive.pending.as_ref().ok_or("pending HEVC")?;
        // Stage the exact auxiliary native recording first. Its existing root will be
        // reverified by work publication, so the next real rename is the complete work root.
        let auxiliary = SlotName::parse(&format!(
            "{}-w",
            pin.slot().as_str().strip_suffix("-r").ok_or("work route")?
        ))?;
        {
            let mut job = RecordingPublication::new(
                window.publication_plan(),
                &mut publisher,
                auxiliary,
                bytes,
                1000,
            )?;
            let mut published = false;
            for _ in 0..5 {
                if let RecordingProgress::Published(receipt) = job.step(0, &NeverCancel)? {
                    assert_eq!(receipt.root, root);
                    assert_eq!(receipt.claims.local, LocalPublicationState::Durable);
                    published = true;
                    break;
                }
            }
            assert!(published);
        }
        let work = PreparedHevcArchiveWork::prepare(
            &retired.archive,
            &publisher,
            ArchiveWorkLimits::default(),
            &NeverCancel,
        )?;
        assert_eq!(work.root(), pin.root());
        assert_eq!(work.slot(), pin.slot());
        publisher.inject_crash_at(PublishCutPoint::AfterRootRename);
        assert!(work.publish(&mut publisher, 0, 1000, &NeverCancel).is_err());
        assert_eq!(
            publisher
                .root(pin.slot())
                .ok_or("work rename did not occur")?
                .state,
            LocalPublicationState::Visible
        );
        assert_eq!(pins.anchor(), anchor);
        assert!(pins.state().candidate().is_some());
        assert!(pins.state().last_confirmed().is_none());
        assert!(retired.archive.snapshot.windows().is_empty());
        assert_eq!(window.objects().source, source_bytes);
        assert!(publisher.root(&namespace()?.window_slot(0)?).is_none());
        (anchor, root, source_bytes)
    };
    let confirmed = {
        let (mut publisher, mut pins) = reopen(&path, Some(anchor))?;
        let restored = pins.restore_work(
            &mut publisher,
            ArchiveWorkLimits::default(),
            0,
            1000,
            &NeverCancel,
        )?;
        assert_eq!(
            restored.window.as_ref().ok_or("restored window")?.root,
            root
        );
        assert!(restored.confirmation.is_some());
        assert!(restored.catalog.is_none());
        assert_eq!(
            (
                restored.durable_windows,
                restored.indexed_windows,
                restored.pages
            ),
            (1, 0, 0)
        );
        assert_eq!(pins.anchor().sequence, 3);
        let recording = load_hevc_recording(
            &publisher,
            &namespace()?.window_slot(0)?,
            root,
            &source::scope()?,
            &NeverCancel,
        )?;
        assert_eq!(recording.objects().source, source_bytes);
        assert_eq!(decode_pixels(&recording)?, 4);
        pins.anchor()
    }; // The successful restoration response is now lost too.
    let (mut publisher, mut pins) = reopen(&path, Some(confirmed))?;
    let roots = publisher.visible_roots().count();
    let restored = pins.restore_work(
        &mut publisher,
        ArchiveWorkLimits::default(),
        1,
        1000,
        &NeverCancel,
    )?;
    assert_eq!(
        restored.window.ok_or("retry window")?.outcome,
        PublishOutcome::AlreadyPublished
    );
    assert!(restored.confirmation.is_none());
    assert_eq!(pins.anchor(), confirmed);
    assert_eq!(publisher.visible_roots().count(), roots);
    assert_eq!(finish(&mut writer(&mut publisher, &mut pins)?)?, (1, 1));
    Ok(())
}

#[test]
fn confirmation_budget_failure_retains_actual_work_receipt_before_any_normal_publication() -> Test {
    let path = fresh("protected_hevc_confirmation_limit")?;
    let root = {
        let mut publisher = LocalRootPublisher::open(path.join("media"), storage())?;
        let mut pins = create(
            &path,
            ArchivePinLimits {
                max_records: 2,
                ..ArchivePinLimits::default()
            },
        )?;
        let mut writer = writer(&mut publisher, &mut pins)?;
        let root = offer(&mut writer, 0)?;
        let _ = writer.step(0, &NeverCancel)?;
        assert!(matches!(
            writer.step(0, &NeverCancel),
            Err(ArchivePinError::Limit)
        ));
        assert!(matches!(
            writer.step(0, &NeverCancel),
            Err(ArchivePinError::Fenced)
        ));
        let retired = writer.retire();
        let unrecorded = retired
            .unrecorded_confirmation
            .ok_or("lost durable work receipt")?;
        assert_eq!(unrecorded.receipt.root, unrecorded.checkpoint.root());
        assert_eq!(
            unrecorded.receipt.claims.local,
            LocalPublicationState::Durable
        );
        assert_eq!(
            retired
                .writer
                .archive
                .pending
                .ok_or("lost HEVC")?
                .manifest()
                .root(),
            root
        );
        assert!(retired.pins.candidate().is_some());
        assert!(retired.pins.last_confirmed().is_none());
        assert!(publisher.root(&namespace()?.window_slot(0)?).is_none());
        root
    };
    // A separately supplied larger metadata budget permits the same cold candidate to settle.
    let (mut publisher, mut pins) = reopen(&path, None)?;
    let result = pins.restore_work(
        &mut publisher,
        ArchiveWorkLimits::default(),
        0,
        1000,
        &NeverCancel,
    )?;
    assert_eq!(result.window.ok_or("window")?.root, root);
    assert_eq!(result.journal_anchor.sequence, 3);
    Ok(())
}

#[test]
fn missing_new_candidate_never_falls_back_to_the_prior_confirmed_hevc_page() -> Test {
    let path = fresh("protected_hevc_no_fallback")?;
    let (anchor, predecessor) = {
        let mut publisher = LocalRootPublisher::open(path.join("media"), storage())?;
        let mut pins = create(&path, ArchivePinLimits::default())?;
        let mut first = writer(&mut publisher, &mut pins)?;
        offer(&mut first, 0)?;
        assert_eq!(finish(&mut first)?, (1, 1));
        let _ = first.retire();
        let predecessor = pins
            .state()
            .last_confirmed()
            .cloned()
            .ok_or("prior confirmation")?;
        let mut next = writer(&mut publisher, &mut pins)?;
        offer(&mut next, 90_000)?;
        assert!(matches!(
            next.step(0, &NeverCancel)?,
            JournaledArchiveProgress::PinPersisted { .. }
        ));
        assert_eq!(next.pin_state().last_confirmed(), Some(&predecessor));
        (next.journal_anchor(), predecessor)
    };
    let (mut publisher, mut pins) = reopen(&path, Some(anchor))?;
    let candidate = pins.state().candidate().cloned().ok_or("new candidate")?;
    let roots = publisher.visible_roots().count();
    assert!(publisher.root(candidate.slot()).is_none());
    assert!(
        pins.restore_work(
            &mut publisher,
            ArchiveWorkLimits::default(),
            0,
            1000,
            &NeverCancel
        )
        .is_err()
    );
    assert!(writer(&mut publisher, &mut pins).is_err());
    assert_eq!(pins.anchor(), anchor);
    assert_eq!(pins.state().candidate(), Some(&candidate));
    assert_eq!(pins.state().last_confirmed(), Some(&predecessor));
    assert_eq!(publisher.visible_roots().count(), roots);
    assert!(publisher.root(&namespace()?.window_slot(1)?).is_none());
    Ok(())
}

#[test]
fn codec_domains_reject_hevc_work_and_pins_through_avc_entrypoints_without_mutation() -> Test {
    let path = fresh("protected_hevc_codec_pinning")?;
    let mut publisher = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = create(&path, ArchivePinLimits::default())?;
    let pin = pin_candidate(&mut publisher, &mut pins, true)?;
    let restored = load_hevc_archive_work(
        &publisher,
        pin.slot(),
        pin.root(),
        ArchiveWorkLimits::default(),
        &NeverCancel,
    )?;
    assert_eq!(
        hevc_archive_retirement_digest(&restored)?,
        pin.retirement_digest()
    );
    assert_eq!(
        PreparedHevcArchiveWork::prepare(
            &restored,
            &publisher,
            ArchiveWorkLimits::default(),
            &NeverCancel
        )?
        .root(),
        pin.root()
    );
    assert_eq!(
        restored
            .pending
            .ok_or("native HEVC missing")?
            .manifest()
            .kind(),
        "hevc_recording_window_v1"
    );
    let manifest =
        fss_object::ObjectManifest::from_canonical_bytes(&publisher.spool().read(pin.root())?)?;
    assert_eq!(manifest.kind(), HEVC_ARCHIVE_WORK_KIND);
    assert!(
        load_archive_work(
            &publisher,
            pin.slot(),
            pin.root(),
            ArchiveWorkLimits::default(),
            &NeverCancel
        )
        .is_err()
    );
    let mut avc = ArchivePinJournal::create(
        path.join("avc-pins"),
        scope()?,
        ArchivePinLimits::default(),
        &NeverCancel,
    )?;
    let avc_anchor = avc.anchor();
    let before = std::fs::read(path.join("avc-pins/pins.journal"))?;
    assert!(matches!(
        avc.persist_candidate(&pin, &NeverCancel),
        Err(ArchivePinError::History)
    ));
    assert_eq!(avc.anchor(), avc_anchor);
    assert_eq!(std::fs::read(path.join("avc-pins/pins.journal"))?, before);
    // Original AVC genesis bytes remain exact, despite the shared implementation.
    let report = recover_bytes(&before)?;
    let mut expected = CanonicalEncoder::new();
    expected.text("fss.archive_pin_journal.v1");
    expected.digest(scope()?.journal_id);
    expected.digest(scope()?.archive_namespace);
    expected.tag(0);
    assert_eq!(report.records()[0].payload(), expected.finish_checked()?);
    let anchor = pins.anchor();
    drop(pins);
    let hevc_bytes = std::fs::read(path.join("pins/pins.journal"))?;
    assert!(matches!(
        ArchivePinJournal::open_complete(
            path.join("pins"),
            scope()?,
            Some(anchor),
            ArchivePinLimits::default(),
            &NeverCancel
        ),
        Err(ArchivePinError::History)
    ));
    assert_eq!(std::fs::read(path.join("pins/pins.journal"))?, hevc_bytes);
    let _reopened = HevcArchivePinJournal::open_complete(
        path.join("pins"),
        scope()?,
        Some(anchor),
        ArchivePinLimits::default(),
        &NeverCancel,
    )?;
    Ok(())
}

#[test]
fn damaged_original_rtp_prevents_cold_confirmation_and_retains_the_exact_candidate() -> Test {
    let path = fresh("protected_hevc_damaged_source")?;
    let mut publisher = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = create(&path, ArchivePinLimits::default())?;
    let pin = pin_candidate(&mut publisher, &mut pins, true)?;
    let source_digest = {
        let work = pins.load_work(
            ArchivePinPhase::Candidate,
            &publisher,
            ArchiveWorkLimits::default(),
            &NeverCancel,
        )?;
        ContentDigest::sha256(work.pending.ok_or("original HEVC")?.objects().source)
    };
    let anchor = pins.anchor();
    let roots = publisher.visible_roots().count();
    corrupt(&path.join("media"), source_digest)?;
    assert!(
        pins.restore_work(
            &mut publisher,
            ArchiveWorkLimits::default(),
            0,
            1000,
            &NeverCancel
        )
        .is_err()
    );
    assert_eq!(pins.anchor(), anchor);
    assert_eq!(
        pins.state().candidate().ok_or("candidate lost")?.root(),
        pin.root()
    );
    assert!(pins.state().last_confirmed().is_none());
    assert_eq!(publisher.visible_roots().count(), roots);
    assert!(publisher.root(&namespace()?.window_slot(0)?).is_none());
    Ok(())
}

#[test]
fn work_bounds_and_cancelled_publication_keep_original_native_hevc_without_custody_claims() -> Test
{
    let path = fresh("protected_hevc_work_bounds")?;
    let mut publisher = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut writer = HevcRecordingArchiveWriter::open(
        &mut publisher,
        namespace()?,
        archive_limits(),
        0,
        1000,
        &NeverCancel,
    )?;
    let recording = fixture::window(0)?;
    let root = recording.manifest().root();
    let bytes = recording.byte_len();
    writer.offer(recording, bytes, 0)?;
    let work = writer.retire();
    for limits in [
        ArchiveWorkLimits {
            max_pending_bytes: 0,
            ..ArchiveWorkLimits::default()
        },
        ArchiveWorkLimits {
            max_graph_objects: 1,
            ..ArchiveWorkLimits::default()
        },
        ArchiveWorkLimits {
            max_new_bytes: 0,
            ..ArchiveWorkLimits::default()
        },
    ] {
        assert!(PreparedHevcArchiveWork::prepare(&work, &publisher, limits, &NeverCancel).is_err());
    }
    let prepared = PreparedHevcArchiveWork::prepare(
        &work,
        &publisher,
        ArchiveWorkLimits::default(),
        &NeverCancel,
    )?;
    assert!(
        prepared
            .publish(&mut publisher, 0, 1000, &hevc_archive_support::Stop)
            .is_err()
    );
    assert!(matches!(
        prepared.publish(&mut publisher, 1000, 1000, &NeverCancel),
        Err(ArchiveError::Deadline)
    ));
    assert_eq!(
        work.pending
            .ok_or("refusal lost original")?
            .manifest()
            .root(),
        root
    );
    assert_eq!(publisher.visible_roots().count(), 0);
    Ok(())
}

#[test]
fn damaged_independent_tip_fences_live_intake_before_source_checkpoint() -> Test {
    let path = fresh("protected_hevc_tip_fence")?;
    let mut publisher = LocalRootPublisher::open(path.join("media"), storage())?;
    let mut pins = create(&path, ArchivePinLimits::default())?;
    let mut writer = writer(&mut publisher, &mut pins)?;
    let root = offer(&mut writer, 0)?;
    let path = path.join("pins/pins.journal");
    let mut bytes = std::fs::read(&path)?;
    *bytes.last_mut().ok_or("empty journal")? ^= 1;
    std::fs::write(path, bytes)?;
    assert!(writer.verify_pins(&NeverCancel).is_err());
    assert!(matches!(
        writer.step(0, &NeverCancel),
        Err(ArchivePinError::Fenced)
    ));
    let next = fixture::window(90_000)?;
    let next_root = next.manifest().root();
    let reserved = next.byte_len();
    let refused = writer
        .offer(next, reserved, 0)
        .err()
        .ok_or("fenced writer admitted source")?;
    assert_eq!(refused.recording.manifest().root(), next_root);
    let retired = writer.retire();
    assert_eq!(
        retired
            .writer
            .archive
            .pending
            .ok_or("old source lost")?
            .manifest()
            .root(),
        root
    );
    assert!(publisher.visible_roots().next().is_none());
    Ok(())
}

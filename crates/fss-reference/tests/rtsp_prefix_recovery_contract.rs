#![forbid(unsafe_code)]
//! Offline recovery of native fixture input; no camera, credentials or live network.
mod recording_support;

use fss_core::ContentDigest;
use fss_ledger::IncompleteTailPolicy;
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel};
use fss_reference::rtsp::archive_pins::{
    ArchivePinJournal, ArchivePinLimits, ArchivePinPhase, ArchivePinScope,
    JournaledArchiveProgress, JournaledArchiveWriter,
};
use fss_reference::rtsp::recording::local::load_recording;
use fss_reference::rtsp::recording::{MAX_RECORDING_BYTES, RecordingPacket};
use fss_reference::rtsp::recording_archive::checkpoint::ArchiveWorkLimits;
use fss_reference::rtsp::recording_archive::{
    ArchiveLimits, ArchiveNamespace, ArchiveSnapshot, ArchiveWriteProgress,
};
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_collector::{
    CollectedPicture, CollectionStop, CollectorAdmission, CollectorError, CollectorLimits,
    RecordingCollector, RecordingTiming, UnsealedRecording,
};
use recording_support::{Error, fixture, packet, scope};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

type Test<T = ()> = Result<T, Error>;
const NOW: u64 = 100;
const DECODE_START: u64 = 700;

fn collect(fragmented: bool, tail: bool, corrupt: bool) -> Test<RecordingCollector> {
    let f = fixture(31, fragmented)?;
    let key = f.pictures.first().ok_or("fixture picture missing")?.key();
    let last = f.packets.last().ok_or("fixture source missing")?.0;
    let mut collector =
        RecordingCollector::new(scope()?, key, 96, 90_000, CollectorLimits::default())?;
    for (sequence, received_ns, mut bytes) in f.packets {
        // RTP framing stays valid, while the stored original no longer matches
        // the already assembled picture. Native source replay must discover this.
        if corrupt && sequence == last {
            let byte = bytes.get_mut(12).ok_or("fixture payload missing")?;
            *byte ^= 1;
        }
        collector.push_source(
            key,
            RecordingPacket {
                sequence,
                received_ns,
                bytes: &bytes,
            },
            NOW,
        )?;
    }
    for (index, picture) in f.pictures.into_iter().enumerate() {
        match collector.push_picture(
            CollectedPicture {
                picture,
                timing: RecordingTiming {
                    decode_time: DECODE_START + index as u64 * 3600,
                    duration: 3600,
                    composition_offset: 0,
                },
            },
            NOW + 1,
        ) {
            CollectorAdmission::Accepted {
                window_ready: false,
                ..
            } => {}
            _ => return Err("fixture was not accepted into one unsealed window".into()),
        }
    }
    if tail {
        let sequence = last.checked_add(1).ok_or("fixture sequence overflow")?;
        let bytes = packet(u16::try_from(sequence)?, false, &[0x61, 0x80]);
        collector.push_source(
            key,
            RecordingPacket {
                sequence,
                received_ns: 777,
                bytes: &bytes,
            },
            NOW + 2,
        )?;
    }
    Ok(collector)
}

fn retired(fragmented: bool, tail: bool, reason: CollectionStop) -> Test<UnsealedRecording> {
    Ok(collect(fragmented, tail, false)?.interrupt(NOW + 3, reason)?)
}

fn source_snapshot(input: &UnsealedRecording) -> Vec<(u64, u64, Vec<u8>)> {
    input
        .sources
        .iter()
        .map(|s| (s.sequence(), s.received_ns(), s.bytes().to_vec()))
        .collect()
}

#[test]
fn recovered_single_nal_and_fu_a_match_the_ordinary_native_seal() -> Test {
    for fragmented in [false, true] {
        let mut ordinary = collect(fragmented, false, false)?;
        assert!(ordinary.seal(NOW + 3)?);
        let expected = ordinary.take_ready().ok_or("normal seal missing")?;
        let input = retired(fragmented, false, CollectionStop::InputDiscontinuity)?;
        let count = input.sources.len();
        let recovered = input.prepare_verified_prefix(scope()?, 90_000, MAX_RECORDING_BYTES)?;
        assert_eq!(recovered.selected_packets, count);
        assert_eq!(
            recovered.recording.manifest().root(),
            expected.manifest().root()
        );
        assert_eq!(
            recovered.recording.objects().source,
            expected.objects().source
        );
        assert_eq!(
            recovered.recording.objects().media,
            expected.objects().media
        );
        assert_eq!(
            recovered.recording.objects().index,
            expected.objects().index
        );
        assert!(recovered.remainder.sources.is_empty());
        assert!(recovered.remainder.pictures.is_empty());
    }
    Ok(())
}

#[test]
fn trailing_datagram_is_returned_whole_with_original_receive_time() -> Test {
    let input = retired(true, true, CollectionStop::Cancelled)?;
    let key = input.key;
    let sources = source_snapshot(&input);
    let tail = sources.last().ok_or("tail missing")?.clone();
    let recovered = input.prepare_verified_prefix(scope()?, 90_000, MAX_RECORDING_BYTES)?;
    assert_eq!(recovered.selected_packets + 1, sources.len());
    assert_eq!(source_snapshot(&recovered.remainder), vec![tail]);
    assert_eq!(recovered.remainder.key, key);
    assert_eq!(recovered.remainder.reason, CollectionStop::Cancelled);
    assert!(recovered.remainder.pictures.is_empty());
    Ok(())
}

#[test]
fn preparation_never_relabels_the_original_stop_as_eof() -> Test {
    for reason in [
        CollectionStop::InputDiscontinuity,
        CollectionStop::Deadline,
        CollectionStop::Cancelled,
        CollectionStop::EndOfInput,
        CollectionStop::OwnerDiscard,
    ] {
        let input = retired(false, true, reason)?;
        let recovered = input.prepare_verified_prefix(scope()?, 90_000, MAX_RECORDING_BYTES)?;
        assert_eq!(recovered.original_stop, reason);
        assert_eq!(recovered.remainder.reason, reason);
    }
    Ok(())
}

#[test]
fn expired_collector_can_preserve_its_prefix_without_resetting_its_clock() -> Test {
    let mut collector = collect(true, false, false)?;
    let deadline = collector
        .next_wake_ns()
        .ok_or("collector deadline missing")?;
    let input = collector
        .poll(deadline)?
        .ok_or("expired source not returned")?;
    assert_eq!(input.reason, CollectionStop::Deadline);
    let recovered = input.prepare_verified_prefix(scope()?, 90_000, MAX_RECORDING_BYTES)?;
    assert_eq!(recovered.original_stop, CollectionStop::Deadline);
    assert_eq!(collector.retained_samples(), 0);
    assert_eq!(collector.seal(NOW + 3), Err(CollectorError::ClockReversed));
    Ok(())
}

#[test]
fn too_small_output_bound_returns_all_input_for_an_exact_offline_retry() -> Test {
    let mut ordinary = collect(true, true, false)?;
    ordinary.seal(NOW + 3)?;
    let expected = ordinary.take_ready().ok_or("expected window")?;
    let input = retired(true, true, CollectionStop::InputDiscontinuity)?;
    let before = source_snapshot(&input);
    let timings: Vec<_> = input.pictures.iter().map(|p| p.timing).collect();
    let refused = input
        .prepare_verified_prefix(scope()?, 90_000, expected.byte_len() - 1)
        .err()
        .ok_or("undersized recovery unexpectedly succeeded")?;
    assert_eq!(refused.reason, CollectorError::Capacity);
    assert_eq!(source_snapshot(&refused.original), before);
    assert_eq!(
        refused
            .original
            .pictures
            .iter()
            .map(|p| p.timing)
            .collect::<Vec<_>>(),
        timings
    );
    let recovered =
        refused
            .original
            .prepare_verified_prefix(scope()?, 90_000, expected.byte_len())?;
    assert_eq!(
        recovered.recording.manifest().root(),
        expected.manifest().root()
    );
    assert_eq!(recovered.remainder.sources.len(), 1);
    Ok(())
}

#[test]
fn invalid_scope_receiver_clock_and_size_bounds_return_originals() -> Test {
    for variant in 0..6 {
        let mut input = retired(true, true, CollectionStop::Cancelled)?;
        let mut original_scope = scope()?;
        let mut time_scale = 90_000;
        let mut limit = MAX_RECORDING_BYTES;
        match variant {
            0 => original_scope.generation += 1,
            1 => input.key.ssrc += 1,
            2 => input.key.ingress = 0,
            3 => time_scale = 0,
            4 => limit = 0,
            _ => limit = MAX_RECORDING_BYTES + 1,
        }
        let before = source_snapshot(&input);
        let refused = input
            .prepare_verified_prefix(original_scope, time_scale, limit)
            .err()
            .ok_or("invalid recovery accepted")?;
        assert_eq!(source_snapshot(&refused.original), before);
        assert_eq!(refused.original.pictures.len(), 1);
        assert!(matches!(
            refused.reason,
            CollectorError::Configuration | CollectorError::StreamMismatch
        ));
    }
    Ok(())
}

#[test]
fn missing_reordered_and_changed_originals_cannot_become_a_recording() -> Test {
    for variant in 0..3 {
        let mut input = collect(true, false, variant == 2)?
            .interrupt(NOW + 3, CollectionStop::InputDiscontinuity)?;
        if variant == 0 {
            drop(input.sources.pop());
        } else if variant == 1 {
            input.sources.swap(0, 1);
        }
        let before = source_snapshot(&input);
        let refused = input
            .prepare_verified_prefix(scope()?, 90_000, MAX_RECORDING_BYTES)
            .err()
            .ok_or("damaged source accepted")?;
        assert_eq!(source_snapshot(&refused.original), before);
        assert_eq!(refused.original.pictures.len(), 1);
        if variant == 1 {
            assert_eq!(refused.reason, CollectorError::SourceOrder);
        }
    }
    Ok(())
}

#[test]
fn invalid_or_overflowing_timing_does_not_consume_any_input() -> Test {
    for variant in 0..3 {
        let mut input = retired(false, false, CollectionStop::Cancelled)?;
        let timing = &mut input.pictures.first_mut().ok_or("picture")?.timing;
        match variant {
            0 => timing.duration = 0,
            1 => timing.decode_time = u64::MAX,
            _ => {
                timing.decode_time = 0;
                timing.composition_offset = -1;
            }
        }
        let before = source_snapshot(&input);
        let before_timing = input.pictures[0].timing;
        let refused = input
            .prepare_verified_prefix(scope()?, 90_000, MAX_RECORDING_BYTES)
            .err()
            .ok_or("invalid timing accepted")?;
        assert_eq!(source_snapshot(&refused.original), before);
        assert_eq!(refused.original.pictures[0].timing, before_timing);
    }
    Ok(())
}

#[test]
fn source_without_a_complete_picture_does_not_invent_a_sample() -> Test {
    let mut input = retired(true, true, CollectionStop::InputDiscontinuity)?;
    input.pictures.clear();
    let before = source_snapshot(&input);
    let refused = input
        .prepare_verified_prefix(scope()?, 90_000, MAX_RECORDING_BYTES)
        .err()
        .ok_or("empty picture inventory accepted")?;
    assert_eq!(refused.reason, CollectorError::UnverifiedPicture);
    assert_eq!(source_snapshot(&refused.original), before);
    Ok(())
}

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for _ in 0..256 {
            let path = std::env::temp_dir().join(format!(
                "fss-offline-prefix-{}-{}",
                std::process::id(),
                NEXT_PATH.fetch_add(1, Ordering::Relaxed),
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("fixture directory allowance exhausted".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn recovered_prefix_crosses_independent_pin_barriers_and_reopens_cold() -> Test {
    let directory = Directory::new()?;
    let namespace = ArchiveNamespace::new(CatalogScope {
        recording: scope()?,
        decode_clock: ContentDigest::sha256(b"original offline recovery decode clock"),
        time_scale: 90_000,
    })?;
    let pin_scope = || ArchivePinScope {
        journal_id: ContentDigest::sha256(b"explicit offline recovery journal"),
        archive_namespace: namespace.digest(),
    };
    let storage = || {
        LocalPublicationLimits::new(
            128,
            1024,
            128,
            1024,
            SpoolLimits::new(1024, 16 * 1024 * 1024, 1024 * 1024, 1024),
        )
    };
    let limits = || ArchiveLimits {
        max_windows: 8,
        max_pages: 8,
        max_scan_roots: 256,
        windows_per_page: 2,
    };
    let recovered = retired(true, true, CollectionStop::InputDiscontinuity)?
        .prepare_verified_prefix(scope()?, 90_000, MAX_RECORDING_BYTES)?;
    let expected_root = recovered.recording.manifest().root();
    let expected_source = recovered.recording.objects().source.to_vec();
    let expected_media = recovered.recording.objects().media.to_vec();
    assert_eq!(recovered.remainder.sources.len(), 1);
    let anchor = {
        let mut publisher = LocalRootPublisher::open(directory.0.join("media"), storage())?;
        let mut pins = ArchivePinJournal::create(
            directory.0.join("pins"),
            pin_scope(),
            ArchivePinLimits::default(),
            &NeverCancel,
        )?;
        let mut writer = JournaledArchiveWriter::open(
            &mut publisher,
            &mut pins,
            namespace.clone(),
            limits(),
            ArchiveWorkLimits::default(),
            256,
            0,
            1000,
            &NeverCancel,
        )?;
        let bytes = recovered.recording.byte_len();
        let _admission = writer.offer(recovered.recording, bytes, 0)?;
        assert!(matches!(writer.step(0, &NeverCancel)?,
            JournaledArchiveProgress::PinPersisted { receipt, .. }
                if receipt.phase() == ArchivePinPhase::Candidate));
        assert_eq!(writer.snapshot().windows().len(), 0);
        assert!(matches!(writer.step(0, &NeverCancel)?,
            JournaledArchiveProgress::WorkConfirmed { pin_receipt, .. }
                if pin_receipt.phase() == ArchivePinPhase::Confirmed));
        assert_eq!(writer.snapshot().windows().len(), 0);
        assert!(matches!(
            writer.step(0, &NeverCancel)?,
            JournaledArchiveProgress::Archive(ArchiveWriteProgress::WindowDurable {
                ordinal: 0,
                ..
            })
        ));
        writer.finish(1)?;
        let mut finished = false;
        for _ in 0..64 {
            if let JournaledArchiveProgress::Archive(ArchiveWriteProgress::Finished {
                windows: 1,
                pages: 1,
                ..
            }) = writer.step(1, &NeverCancel)?
            {
                finished = true;
                break;
            }
        }
        assert!(finished, "bounded protected drain did not finish");
        let anchor = writer.journal_anchor();
        drop(writer);
        pins.require_settled(&publisher, ArchiveWorkLimits::default(), &NeverCancel)?;
        anchor
    };
    let publisher = LocalRootPublisher::open(directory.0.join("media"), storage())?;
    let mut pins = ArchivePinJournal::open_existing(
        directory.0.join("pins"),
        pin_scope(),
        Some(anchor),
        ArchivePinLimits::default(),
        IncompleteTailPolicy::Reject,
        &NeverCancel,
    )?;
    pins.require_settled(&publisher, ArchiveWorkLimits::default(), &NeverCancel)?;
    let snapshot = ArchiveSnapshot::load(&publisher, namespace.clone(), limits(), &NeverCancel)?;
    assert_eq!(snapshot.windows().len(), 1);
    assert_eq!(snapshot.indexed_windows(), 1);
    assert_eq!(snapshot.windows()[0].root(), expected_root);
    let recording = load_recording(
        &publisher,
        &namespace.window_slot(0)?,
        expected_root,
        &scope()?,
        &NeverCancel,
    )?;
    assert_eq!(recording.objects().source, expected_source.as_slice());
    assert_eq!(recording.objects().media, expected_media.as_slice());
    assert_eq!(recovered.original_stop, CollectionStop::InputDiscontinuity);
    Ok(())
}

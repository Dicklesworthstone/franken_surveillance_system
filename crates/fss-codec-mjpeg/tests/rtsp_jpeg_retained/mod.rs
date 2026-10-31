#![forbid(unsafe_code)]
//! Real root-last original custody, cold reopen, native reconstruction and complete pixels.

use super::{JPEG, KEY, ORACLE, Test, packet, scan};
use crate::rtsp::datagram_archive::prefix::DatagramPrefix;
use crate::rtsp::datagram_archive::{
    DatagramArchive, DatagramArchiveError, DatagramArchiveLimits, DatagramPin, DatagramScope,
};
use crate::rtsp::datagram_reconstruction::jpeg::{
    DatagramJpegReplay, JpegFrameProvenance, JpegReplayBounds, JpegReplayError, JpegReplaySpec,
    JpegReplayStep,
};
use crate::rtsp::framed::RtspWireIntake;
use crate::rtsp::jpeg_client::pictures::decode_luma_frame;
use crate::rtsp::tcp::{TcpBinding, TcpSecurityPolicy};
use fss_codec_mjpeg::{DecodeBudget, DecodeLimits};
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_object::SpoolLimits;
use fss_packet::jpeg::{JpegError, JpegFrame, JpegLimits, JpegReceiveError, JpegReceivePoll};
use fss_packet::{ReorderDisposition, ReorderLimits};
use fss_publication::{
    LocalPublicationLimits, LocalPublicationState, LocalRootPublisher, NeverCancel,
    PublishCancellation, PublishCutPoint,
};
use std::cell::Cell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for _ in 0..256 {
            let path = std::env::temp_dir().join(format!(
                "fss-jpeg-retained-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("fixture directory capacity".into())
    }
    fn open(&self) -> Test<LocalRootPublisher> {
        Ok(LocalRootPublisher::open(
            &self.0,
            LocalPublicationLimits::new(
                256,
                8,
                256,
                1024,
                SpoolLimits::new(1024, 16 * 1024 * 1024, 65_536, 1024),
            ),
        )?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn scope() -> Test<DatagramScope> {
    Ok(DatagramScope {
        binding: TcpBinding::new(
            KEY,
            "127.0.0.1:554".parse()?,
            "camera.local",
            TcpSecurityPolicy::OwnerApprovedPlaintext,
        )?,
        channels: (0, 1),
        receive_clock: ContentDigest::sha256(b"fixture original parser-completion receive clock"),
        retention_evidence: ContentDigest::sha256(
            b"fixture explicit original RTP and RTCP custody",
        ),
    })
}
fn limits() -> DatagramArchiveLimits {
    DatagramArchiveLimits {
        max_datagrams: 64,
        max_payload_bytes: 4 * 1024 * 1024,
        max_scan_roots: 1024,
        max_spool_object_bytes: 65_536,
    }
}
fn spec() -> JpegReplaySpec {
    JpegReplaySpec {
        payload_type: 26,
        reorder: ReorderLimits {
            max_packets: 32,
            max_bytes: 65_536,
            max_delay_ns: 1000,
            ..ReorderLimits::default()
        },
        jpeg: JpegLimits {
            max_frame_bytes: 65_536,
            max_fragment_packets: 64,
            max_pending_age_ns: 100,
            max_cached_quantizers: 4,
            max_dimension: 64,
        },
        reduced_rtcp: true,
        configuration_evidence: ContentDigest::sha256(
            b"fixture exact accepted JPEG/90000 description",
        ),
    }
}
fn bounds() -> JpegReplayBounds {
    JpegReplayBounds {
        max_source_bytes: 4 * 1024 * 1024,
        max_steps: 512,
        deadline_ns: 10_000,
    }
}
fn work() -> WorkBudget<'static> {
    WorkBudget::new(100_000_000)
}
fn add(
    archive: &mut DatagramArchive,
    publisher: &mut LocalRootPublisher,
    channel: u8,
    now: u64,
    bytes: &[u8],
) -> Test<DatagramPin> {
    let mut wire = vec![b'$', channel];
    wire.extend_from_slice(&u16::try_from(bytes.len())?.to_be_bytes());
    wire.extend_from_slice(bytes);
    let mut intake = RtspWireIntake::new();
    intake.ingest(&wire, now)?;
    let frame = intake.poll(now)?.ok_or("missing actual source frame")?;
    let plan = archive.prepare_frame(&frame, &mut work())?;
    let publication = archive.publish(&plan, publisher, &NeverCancel, &mut work())?;
    assert_eq!(
        publication.local.claims.local,
        LocalPublicationState::Durable
    );
    Ok(publication.record.pin)
}
fn rr() -> Vec<u8> {
    let mut bytes = vec![0x80, 201, 0, 1];
    bytes.extend_from_slice(&KEY.ssrc.to_be_bytes());
    bytes
}
fn whole(sequence: u16) -> Test<Vec<u8>> {
    packet(26, sequence, 0..scan()?.len(), true)
}
fn quantized(sequence: u16, explicit: bool) -> Test<Vec<u8>> {
    let mut original = whole(sequence)?;
    original[17] = 128;
    original[4..8].copy_from_slice(&(u32::from(sequence) * 9000).to_be_bytes());
    let mut out = original[..20].to_vec();
    out.extend_from_slice(&[0, 0, 0, if explicit { 128 } else { 0 }]);
    if explicit {
        let mut tables = [0; 128];
        let mut mask = 0;
        let mut at = 2;
        while at + 4 <= JPEG.len() {
            let end = at + 2 + usize::from(u16::from_be_bytes([JPEG[at + 2], JPEG[at + 3]]));
            let body = JPEG.get(at + 4..end).ok_or("short fixture JPEG")?;
            if JPEG[at + 1] == 0xdb {
                let (entries, remainder) = body.as_chunks::<65>();
                assert!(remainder.is_empty());
                for table in entries {
                    let id = usize::from(table[0]);
                    assert!(id < 2);
                    tables[id * 64..(id + 1) * 64].copy_from_slice(&table[1..]);
                    mask |= 1 << id;
                }
            }
            if JPEG[at + 1] == 0xda {
                break;
            }
            at = end;
        }
        assert_eq!(mask, 3);
        out.extend_from_slice(&tables);
    }
    out.extend_from_slice(&original[20..]);
    Ok(out)
}
fn replay(archive: &DatagramArchive, publisher: &LocalRootPublisher) -> Test<Vec<JpegReplayStep>> {
    let mut driver = DatagramJpegReplay::new(archive, spec(), bounds(), 0)?;
    let mut steps = Vec::new();
    for _ in 0..512 {
        let step = driver.step(publisher, 1, &NeverCancel, &mut work())?;
        let end = matches!(
            step,
            JpegReplayStep::PrefixExhausted { .. } | JpegReplayStep::Ended
        );
        steps.push(step);
        if end {
            return Ok(steps);
        }
    }
    Err("replay did not yield within fixture bound".into())
}
fn frame(step: &JpegReplayStep) -> Option<(&JpegFrame, &JpegFrameProvenance)> {
    if let JpegReplayStep::Media {
        event:
            JpegReceivePoll::Packet {
                reconstruction: Ok(output),
                ..
            },
        provenance: Some(provenance),
        ..
    } = step
    {
        output.frame.as_deref().map(|frame| (frame, provenance))
    } else {
        None
    }
}

#[test]
fn original_roots_cold_reopen_cached_quantizers_and_native_pixels_remain_connected() -> Test {
    let dir = Directory::new()?;
    let probation = quantized(10, true)?;
    let definition = quantized(11, true)?;
    let reuse = quantized(12, false)?;
    let originals = [
        (0, probation),
        (0, definition.clone()),
        (0, definition),
        (1, rr()),
        (0, reuse),
    ];
    let pin = {
        let mut publisher = dir.open()?;
        let mut archive = DatagramArchive::new(scope()?, limits())?;
        for (index, (channel, bytes)) in originals.iter().enumerate() {
            add(
                &mut archive,
                &mut publisher,
                *channel,
                index as u64 + 10,
                bytes,
            )?;
        }
        archive.pin()
    };
    // All capture/publisher/codec state is gone. Only real published roots and the pin survive.
    let publisher = dir.open()?;
    let selected = DatagramPrefix::recover(
        &publisher,
        scope()?,
        limits(),
        pin,
        &NeverCancel,
        &mut work(),
    )?;
    let first = replay(selected.archive(), &publisher)?;
    let again = replay(selected.archive(), &publisher)?;
    let frames: Vec<_> = first.iter().filter_map(frame).collect();
    assert_eq!(frames.len(), 2);
    assert_eq!(
        frames
            .iter()
            .map(|(_, proof)| proof.digest())
            .collect::<Vec<_>>(),
        again
            .iter()
            .filter_map(frame)
            .map(|(_, proof)| proof.digest())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        frames[1]
            .1
            .dependencies()
            .iter()
            .map(|source| (source.sequence, source.record.pin.datagrams))
            .collect::<Vec<_>>(),
        vec![(11, 2), (12, 5)]
    );
    assert!(frames[1].1.dependencies()[0].sequence < frames[1].0.sequence_interval()[0]);
    assert_eq!(first.iter().filter(|step| matches!(step, JpegReplayStep::Rtp { admission, .. } if admission.transport.disposition == ReorderDisposition::Duplicate)).count(), 1);
    assert!(first.iter().any(|step| matches!(
        step,
        JpegReplayStep::Rtcp {
            validation: Ok(1),
            ..
        }
    )));
    for (image, proof) in &frames {
        assert_eq!(proof.source(), pin);
        assert_eq!(proof.capture_clock(), None);
        assert_eq!(proof.receive_clock(), scope()?.receive_clock);
        assert_eq!(proof.encoded_digest(), ContentDigest::sha256(image.bytes()));
        let mut coverage = vec![0; image.bytes().len()];
        for span in image.source_spans() {
            let dependency = proof
                .dependencies()
                .iter()
                .find(|source| source.sequence == span.sequence)
                .ok_or("missing copied source")?;
            let source = selected.read(
                dependency.record.pin.datagrams,
                &publisher,
                &NeverCancel,
                &mut work(),
            )?;
            assert_eq!(source.record(), dependency.record);
            assert_eq!(
                &source.payload()[span.wire_range.clone()],
                &image.bytes()[span.jpeg_range.clone()]
            );
            for count in &mut coverage[span.jpeg_range.clone()] {
                *count += 1;
            }
        }
        for range in image.generated_ranges() {
            for count in &mut coverage[range.clone()] {
                *count += 1;
            }
        }
        assert!(coverage.iter().all(|count| *count == 1));
    }
    for step in first {
        if let JpegReplayStep::Media {
            event:
                JpegReceivePoll::Packet {
                    reconstruction: Ok(mut output),
                    ..
                },
            provenance: Some(proof),
            ..
        } = step
        {
            let image = *output.frame.take().ok_or("bound image missing")?;
            let picture = decode_luma_frame(
                image,
                proof.encoded_digest().bytes(),
                DecodeLimits::default(),
                &mut DecodeBudget::new(100_000_000),
            )?;
            assert_eq!(picture.pixels().dimensions(), [32, 24]);
            assert_eq!(
                picture.pixels().receipt().encoded_sha256,
                proof.encoded_digest().bytes()
            );
            assert_eq!(picture.pixels().pixels().len(), ORACLE.len());
            for (&actual, &expected) in picture.pixels().pixels().iter().zip(ORACLE) {
                assert!(actual.abs_diff(expected) <= 1);
            }
        }
    }
    assert!(
        matches!(again.last(), Some(JpegReplayStep::PrefixExhausted { source, retired, .. }) if *source == pin && retired.fragment.is_none() && retired.queue.packets == 0)
    );
    for (index, (_, bytes)) in originals.iter().enumerate() {
        assert_eq!(
            selected
                .read(index as u64 + 1, &publisher, &NeverCancel, &mut work())?
                .payload(),
            bytes
        );
    }
    Ok(())
}

#[test]
fn reordered_sequence_wrap_maps_each_fragment_to_actual_arrival_ordinal() -> Test {
    let dir = Directory::new()?;
    let end = scan()?.len();
    let a = end / 3;
    let b = a * 2;
    let originals = [
        whole(65533)?,
        packet(26, 65534, 0..a, false)?,
        packet(26, 0, b..end, true)?,
        packet(26, 65535, a..b, false)?,
    ];
    let pin = {
        let mut publisher = dir.open()?;
        let mut archive = DatagramArchive::new(scope()?, limits())?;
        for (index, bytes) in originals.iter().enumerate() {
            add(&mut archive, &mut publisher, 0, index as u64 + 1, bytes)?;
        }
        archive.pin()
    };
    let publisher = dir.open()?;
    let archive = DatagramArchive::recover(
        &publisher,
        scope()?,
        limits(),
        Some(pin),
        &NeverCancel,
        &mut work(),
    )?;
    let steps = replay(&archive, &publisher)?;
    let frames: Vec<_> = steps.iter().filter_map(frame).collect();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].0.sequence_interval(), [65534, 65536]);
    assert_eq!(
        frames[0]
            .1
            .dependencies()
            .iter()
            .map(|source| (source.sequence, source.record.pin.datagrams))
            .collect::<Vec<_>>(),
        vec![(65534, 2), (65535, 4), (65536, 3)]
    );
    Ok(())
}

#[test]
fn historical_prefix_has_no_invented_eof_or_future_timer_and_growth_does_not_change_selection()
-> Test {
    let dir = Directory::new()?;
    let end = scan()?.len();
    let (selected, head) = {
        let mut publisher = dir.open()?;
        let mut archive = DatagramArchive::new(scope()?, limits())?;
        add(&mut archive, &mut publisher, 0, 10, &whole(10)?)?;
        let selected = add(
            &mut archive,
            &mut publisher,
            0,
            11,
            &packet(26, 11, 0..end / 2, false)?,
        )?;
        let head = add(&mut archive, &mut publisher, 1, 500, &rr())?;
        (selected, head)
    };
    let publisher = dir.open()?;
    let prefix = DatagramPrefix::recover(
        &publisher,
        scope()?,
        limits(),
        selected,
        &NeverCancel,
        &mut work(),
    )?;
    assert_eq!(prefix.pin(), selected);
    assert_eq!(prefix.observed_head(), head);
    let short = replay(prefix.archive(), &publisher)?;
    assert!(short.iter().all(|step| !matches!(
        step,
        JpegReplayStep::ClockAdvanced { .. } | JpegReplayStep::CodecEnded { .. }
    )));
    assert!(short.iter().all(|step| frame(step).is_none()));
    assert!(
        matches!(short.last(), Some(JpegReplayStep::PrefixExhausted { source, replay_ns: 11, retired }) if *source == selected && retired.fragment.as_ref().is_some_and(|fragment| fragment.reason == JpegError::Cancelled))
    );
    let full = DatagramArchive::recover(
        &publisher,
        scope()?,
        limits(),
        Some(head),
        &NeverCancel,
        &mut work(),
    )?;
    let longer = replay(&full, &publisher)?;
    assert!(
        longer
            .iter()
            .any(|step| matches!(step, JpegReplayStep::ClockAdvanced { replay_ns: 111 }))
    );
    assert!(longer.iter().any(|step| matches!(step, JpegReplayStep::Media { event: JpegReceivePoll::JpegDiscarded(discarded), .. } if discarded.reason == JpegError::Deadline)));
    assert_eq!(
        prefix.revalidate(&publisher, &NeverCancel, &mut work())?,
        head
    );
    Ok(())
}

#[test]
fn missing_cached_quantizers_are_an_explicit_source_refusal_not_invented_pixels() -> Test {
    let dir = Directory::new()?;
    let mut publisher = dir.open()?;
    let mut archive = DatagramArchive::new(scope()?, limits())?;
    add(&mut archive, &mut publisher, 0, 1, &whole(10)?)?;
    add(&mut archive, &mut publisher, 0, 2, &quantized(11, false)?)?;
    let steps = replay(&archive, &publisher)?;
    assert!(steps.iter().all(|step| frame(step).is_none()));
    assert!(steps.iter().any(|step| matches!(step, JpegReplayStep::Media {
        event: JpegReceivePoll::Packet { reconstruction: Err(JpegReceiveError::Codec(error)), .. }, provenance: None, ..
    } if error.reason == JpegError::MissingQuantizers)));
    assert_eq!(archive.records().len(), 2);
    Ok(())
}

#[test]
fn cancellation_after_completed_frame_transfers_intact_frame_and_bound_source_map_once() -> Test {
    struct Second(Cell<u32>);
    impl PublishCancellation for Second {
        fn cancel_requested(&self, _: PublishCutPoint) -> bool {
            self.0.set(self.0.get() + 1);
            self.0.get() >= 2
        }
    }
    let dir = Directory::new()?;
    let mut publisher = dir.open()?;
    let mut archive = DatagramArchive::new(scope()?, limits())?;
    add(&mut archive, &mut publisher, 0, 1, &whole(10)?)?;
    add(&mut archive, &mut publisher, 0, 2, &whole(11)?)?;
    let mut driver = DatagramJpegReplay::new(&archive, spec(), bounds(), 0)?;
    for _ in 0..2 {
        assert!(matches!(
            driver.step(&publisher, 1, &NeverCancel, &mut work())?,
            JpegReplayStep::Rtp { .. }
        ));
    }
    let failure = driver
        .step(&publisher, 1, &Second(Cell::new(0)), &mut work())
        .err()
        .ok_or("cancelled output escaped")?;
    assert!(matches!(
        failure.reason,
        JpegReplayError::Source(DatagramArchiveError::Cancelled)
    ));
    let retirement = failure.retirement.ok_or("missing terminal ownership")?;
    assert_eq!(retirement.observations_read, 2);
    let withheld = retirement.withheld.ok_or("lost completed image")?;
    let (image, proof) = frame(&withheld).ok_or("lost bound source map")?;
    assert_eq!(proof.encoded_digest(), ContentDigest::sha256(image.bytes()));
    assert!(driver.cancel().is_none());
    assert!(matches!(
        driver.step(&publisher, 1, &NeverCancel, &mut work())?,
        JpegReplayStep::Ended
    ));
    Ok(())
}

#[test]
fn independent_budget_deadline_clock_and_interpretation_bounds_remain_enforced() -> Test {
    let dir = Directory::new()?;
    let mut publisher = dir.open()?;
    let mut archive = DatagramArchive::new(scope()?, limits())?;
    add(&mut archive, &mut publisher, 0, 1, &whole(10)?)?;
    assert!(
        DatagramJpegReplay::new(
            &archive,
            spec(),
            JpegReplayBounds {
                max_source_bytes: 1,
                ..bounds()
            },
            0
        )
        .is_err()
    );
    let original = DatagramJpegReplay::new(&archive, spec(), bounds(), 10)?.interpretation();
    let mut changed = spec();
    changed.jpeg.max_frame_bytes -= 1;
    assert_ne!(
        original,
        DatagramJpegReplay::new(&archive, changed, bounds(), 10)?.interpretation()
    );
    changed = spec();
    changed.configuration_evidence = ContentDigest::sha256(b"other explicit interpretation");
    assert_ne!(
        original,
        DatagramJpegReplay::new(&archive, changed, bounds(), 10)?.interpretation()
    );
    let mut driver = DatagramJpegReplay::new(&archive, spec(), bounds(), 10)?;
    let refusal = driver
        .step(&publisher, 9, &NeverCancel, &mut work())
        .err()
        .ok_or("clock regression accepted")?;
    assert!(matches!(refusal.reason, JpegReplayError::ClockReversed));
    assert!(refusal.retirement.is_none());
    assert_eq!(driver.observations_read(), 0);
    assert!(matches!(
        driver.step(&publisher, 10, &NeverCancel, &mut work())?,
        JpegReplayStep::Rtp { .. }
    ));
    let refusal = driver
        .step(&publisher, bounds().deadline_ns, &NeverCancel, &mut work())
        .err()
        .ok_or("expired replay proceeded")?;
    assert!(matches!(
        refusal.reason,
        JpegReplayError::Source(DatagramArchiveError::Deadline)
    ));
    assert!(refusal.retirement.is_some());
    let mut driver = DatagramJpegReplay::new(&archive, spec(), bounds(), 0)?;
    let refusal = driver
        .step(&publisher, 0, &NeverCancel, &mut WorkBudget::new(1))
        .err()
        .ok_or("insufficient work accepted")?;
    assert!(matches!(
        refusal.reason,
        JpegReplayError::Source(DatagramArchiveError::Work(_))
    ));
    assert_eq!(
        refusal
            .retirement
            .ok_or("lost work retirement")?
            .observations_read,
        0
    );
    Ok(())
}

#[test]
fn root_corruption_after_recovery_refuses_before_original_admission() -> Test {
    let dir = Directory::new()?;
    let pin = {
        let mut publisher = dir.open()?;
        let mut archive = DatagramArchive::new(scope()?, limits())?;
        add(&mut archive, &mut publisher, 0, 1, &whole(10)?)?
    };
    let publisher = dir.open()?;
    let archive = DatagramArchive::recover(
        &publisher,
        scope()?,
        limits(),
        Some(pin),
        &NeverCancel,
        &mut work(),
    )?;
    let path = publisher.spool().object_path(pin.head);
    std::fs::write(path, b"corrupt original root after index recovery")?;
    let mut driver = DatagramJpegReplay::new(&archive, spec(), bounds(), 0)?;
    let refusal = driver
        .step(&publisher, 1, &NeverCancel, &mut work())
        .err()
        .ok_or("stale index bypassed root read")?;
    assert!(matches!(refusal.reason, JpegReplayError::Source(_)));
    assert_eq!(
        refusal
            .retirement
            .ok_or("missing corruption retirement")?
            .observations_read,
        0
    );
    Ok(())
}

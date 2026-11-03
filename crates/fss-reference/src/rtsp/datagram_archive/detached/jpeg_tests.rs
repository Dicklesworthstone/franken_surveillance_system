#![forbid(unsafe_code)]
//! Existing native scheduler and pixel oracle, with only retained object access replaced.

use super::*;
use crate::rtsp::datagram_reconstruction::jpeg::{
    DatagramJpegReplay, JpegFrameProvenance, JpegReplayBounds, JpegReplayError, JpegReplaySpec,
    JpegReplayStep,
};
use crate::rtsp::jpeg_client::pictures::decode_luma_frame;
use fss_codec_mjpeg::{DecodeBudget, DecodeLimits};
use fss_packet::jpeg::{JpegError, JpegFrame, JpegLimits, JpegReceivePoll};
use fss_packet::{ReorderDisposition, ReorderLimits};

const JPEG: &[u8] =
    include_bytes!("../../../../../fss-codec-mjpeg/tests/fixtures/rtp_jpeg/422_32x24_q50_rst0.jpg");
const ORACLE: &[u8] = include_bytes!(
    "../../../../../fss-codec-mjpeg/tests/fixtures/rtp_jpeg/422_32x24_q50_rst0.ffmpeg.luma"
);

fn scan() -> Test<&'static [u8]> {
    let mut at = 2;
    while at < JPEG.len() {
        let marker = JPEG.get(at..at + 4).ok_or("short fixture marker")?;
        let end = at + 2 + usize::from(u16::from_be_bytes([marker[2], marker[3]]));
        JPEG.get(at..end).ok_or("short fixture segment")?;
        if marker[1] == 0xda {
            return Ok(&JPEG[end..]);
        }
        at = end;
    }
    Err("fixture missing scan".into())
}

fn packet(sequence: u16, range: std::ops::Range<usize>, marker: bool) -> Test<Vec<u8>> {
    let mut bytes = vec![0x80, 26 | if marker { 0x80 } else { 0 }];
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&90_000_u32.to_be_bytes());
    bytes.extend_from_slice(&scope()?.binding.key().ssrc.to_be_bytes());
    bytes.extend_from_slice(&[
        0,
        (range.start >> 16) as u8,
        (range.start >> 8) as u8,
        range.start as u8,
        0,
        50,
        4,
        3,
    ]);
    bytes.extend_from_slice(scan()?.get(range).ok_or("invalid fixture range")?);
    Ok(bytes)
}
fn whole(sequence: u16) -> Test<Vec<u8>> {
    packet(sequence, 0..scan()?.len(), true)
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
fn rr() -> Test<Vec<u8>> {
    let mut bytes = vec![0x80, 201, 0, 1];
    bytes.extend_from_slice(&scope()?.binding.key().ssrc.to_be_bytes());
    Ok(bytes)
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
        configuration_evidence: ContentDigest::sha256(b"detached fixture negotiated JPEG/90000"),
    }
}
fn bounds() -> JpegReplayBounds {
    JpegReplayBounds {
        max_source_bytes: 4 * 1024 * 1024,
        max_steps: 512,
        deadline_ns: 10_000,
    }
}
fn frame(step: &JpegReplayStep) -> Option<(&JpegFrame, &JpegFrameProvenance)> {
    if let JpegReplayStep::Media {
        event:
            JpegReceivePoll::Packet {
                reconstruction: Ok(output),
                ..
            },
        provenance: Some(proof),
        ..
    } = step
    {
        output.frame.as_deref().map(|frame| (frame, proof))
    } else {
        None
    }
}
fn publisher_steps(
    archive: &DatagramArchive,
    publisher: &LocalRootPublisher,
) -> Test<Vec<JpegReplayStep>> {
    let mut replay = DatagramJpegReplay::new(archive, spec(), bounds(), 0)?;
    let mut steps = Vec::new();
    let mut budget = work();
    for _ in 0..512 {
        let step = replay.step(publisher, 1, &NeverCancel, &mut budget)?;
        let ended = matches!(
            step,
            JpegReplayStep::PrefixExhausted { .. }
                | JpegReplayStep::CodecEnded { .. }
                | JpegReplayStep::InputRefused { .. }
        );
        steps.push(step);
        if ended {
            return Ok(steps);
        }
    }
    Err("fixture replay step bound".into())
}
fn detached_steps(
    prefix: &DetachedDatagramPrefix,
    objects: &mut Objects,
) -> Test<Vec<JpegReplayStep>> {
    let mut replay = DatagramJpegReplay::new_detached(prefix, spec(), bounds(), 0)?;
    let mut steps = Vec::new();
    let mut budget = work();
    for _ in 0..512 {
        let step = replay.step_detached(objects, 1, &NeverCancel, &mut budget)?;
        let ended = matches!(
            step,
            JpegReplayStep::PrefixExhausted { .. }
                | JpegReplayStep::CodecEnded { .. }
                | JpegReplayStep::InputRefused { .. }
        );
        steps.push(step);
        if ended {
            assert!(matches!(
                replay.step_detached(objects, 1, &NeverCancel, &mut budget)?,
                JpegReplayStep::Ended
            ));
            return Ok(steps);
        }
    }
    Err("fixture replay step bound".into())
}
fn compare(expected: &[JpegReplayStep], actual: &[JpegReplayStep]) {
    assert_eq!(expected.len(), actual.len());
    for (expected, actual) in expected.iter().zip(actual) {
        // Full typed event debug includes all accounting, pins and proof metadata;
        // original/reconstructed media bytes excluded by Debug are compared below.
        assert_eq!(format!("{expected:?}"), format!("{actual:?}"));
        match (expected, actual) {
            (JpegReplayStep::Rtp { source: a, .. }, JpegReplayStep::Rtp { source: b, .. })
            | (JpegReplayStep::Rtcp { source: a, .. }, JpegReplayStep::Rtcp { source: b, .. })
            | (
                JpegReplayStep::InputRefused { source: a, .. },
                JpegReplayStep::InputRefused { source: b, .. },
            ) => {
                assert_eq!(a.record(), b.record());
                assert_eq!(a.payload(), b.payload());
            }
            (JpegReplayStep::Media { event: a, .. }, JpegReplayStep::Media { event: b, .. }) => {
                assert_eq!(a, b)
            }
            _ => {}
        }
    }
}

#[test]
fn cold_copied_objects_replay_identical_jpegs_quantizer_ancestry_and_native_pixels() -> Test {
    let originals = [
        (0, 10, quantized(10, true)?),
        (0, 11, quantized(11, true)?),
        (0, 12, quantized(11, true)?),
        (1, 13, rr()?),
        (0, 14, quantized(12, false)?),
    ];
    let (mut objects, pin, expected, interpretation, original_path) = {
        let (_directory, publisher, archive) = published(&originals)?;
        (
            Objects::copy(&archive, &publisher)?,
            archive.pin(),
            publisher_steps(&archive, &publisher)?,
            DatagramJpegReplay::new(&archive, spec(), bounds(), 0)?.interpretation(),
            publisher.root_dir().to_path_buf(),
        )
    };
    assert!(!original_path.exists());
    let prefix = recover(&mut objects, pin)?;
    assert_eq!(
        DatagramJpegReplay::new_detached(&prefix, spec(), bounds(), 0)?.interpretation(),
        interpretation
    );
    let actual = detached_steps(&prefix, &mut objects)?;
    compare(&expected, &actual);
    let frames: Vec<_> = actual.iter().filter_map(frame).collect();
    assert_eq!(frames.len(), 2);
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
    assert_eq!(actual.iter().filter(|step| matches!(step, JpegReplayStep::Rtp { admission, .. } if admission.transport.disposition == ReorderDisposition::Duplicate)).count(), 1);
    assert!(actual.iter().any(|step| matches!(
        step,
        JpegReplayStep::Rtcp {
            validation: Ok(1),
            ..
        }
    )));
    for (image, proof) in frames {
        assert_eq!(proof.source(), pin);
        assert_eq!(proof.capture_clock(), None);
        assert_eq!(proof.receive_clock(), scope()?.receive_clock);
        assert_eq!(
            ContentDigest::sha256(&proof.canonical_bytes(image, &mut work())?),
            proof.digest()
        );
        let mut covered = vec![0; image.bytes().len()];
        for span in image.source_spans() {
            let dependency = proof
                .dependencies()
                .iter()
                .find(|source| source.sequence == span.sequence)
                .ok_or("missing source")?;
            let original = prefix.read(
                dependency.record.pin.datagrams,
                &mut objects,
                &NeverCancel,
                &mut work(),
            )?;
            assert_eq!(
                &original.payload()[span.wire_range.clone()],
                &image.bytes()[span.jpeg_range.clone()]
            );
            for count in &mut covered[span.jpeg_range.clone()] {
                *count += 1;
            }
        }
        for range in image.generated_ranges() {
            for count in &mut covered[range.clone()] {
                *count += 1;
            }
        }
        assert!(covered.iter().all(|count| *count == 1));
    }
    for step in actual {
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
            let pixels = decode_luma_frame(
                image,
                proof.encoded_digest().bytes(),
                DecodeLimits::default(),
                &mut DecodeBudget::new(100_000_000),
            )?;
            assert_eq!(pixels.pixels().dimensions(), [32, 24]);
            assert_eq!(pixels.pixels().pixels().len(), ORACLE.len());
            for (&actual, &expected) in pixels.pixels().pixels().iter().zip(ORACLE) {
                assert!(actual.abs_diff(expected) <= 1);
            }
        }
    }
    Ok(())
}

#[test]
fn detached_sequence_wrap_and_reorder_preserve_actual_arrival_dependencies() -> Test {
    let end = scan()?.len();
    let a = end / 3;
    let b = a * 2;
    let (mut objects, pin, expected) = {
        let (_directory, publisher, archive) = published(&[
            (0, 1, whole(65533)?),
            (0, 2, packet(65534, 0..a, false)?),
            (0, 3, packet(0, b..end, true)?),
            (0, 4, packet(65535, a..b, false)?),
        ])?;
        (
            Objects::copy(&archive, &publisher)?,
            archive.pin(),
            publisher_steps(&archive, &publisher)?,
        )
    };
    let prefix = recover(&mut objects, pin)?;
    let actual = detached_steps(&prefix, &mut objects)?;
    compare(&expected, &actual);
    let frames: Vec<_> = actual.iter().filter_map(frame).collect();
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
fn detached_incomplete_tail_does_not_invent_future_timer_or_transport_eof() -> Test {
    for future in [false, true] {
        let mut originals = vec![
            (0, 10, whole(10)?),
            (0, 11, packet(11, 0..scan()?.len() / 2, false)?),
        ];
        if future {
            originals.push((1, 500, rr()?));
        }
        let (mut objects, pin, expected) = {
            let (_directory, publisher, archive) = published(&originals)?;
            (
                Objects::copy(&archive, &publisher)?,
                archive.pin(),
                publisher_steps(&archive, &publisher)?,
            )
        };
        let prefix = recover(&mut objects, pin)?;
        let actual = detached_steps(&prefix, &mut objects)?;
        compare(&expected, &actual);
        assert!(actual.iter().all(|step| frame(step).is_none()));
        if future {
            assert!(
                actual
                    .iter()
                    .any(|step| matches!(step, JpegReplayStep::ClockAdvanced { replay_ns: 111 }))
            );
            assert!(actual.iter().any(|step| matches!(step, JpegReplayStep::Media { event: JpegReceivePoll::JpegDiscarded(discarded), .. } if discarded.reason == JpegError::Deadline)));
        } else {
            assert!(actual.iter().all(|step| !matches!(
                step,
                JpegReplayStep::ClockAdvanced { .. } | JpegReplayStep::CodecEnded { .. }
            )));
            assert!(
                matches!(actual.last(), Some(JpegReplayStep::PrefixExhausted { source, replay_ns: 11, retired }) if *source == pin && retired.fragment.is_some())
            );
        }
    }
    Ok(())
}

#[test]
fn corruption_after_detached_recovery_stops_before_receiver_admission() -> Test {
    let (objects, pin, records) = {
        let (_directory, publisher, archive) =
            published(&[(0, 1, whole(10)?), (0, 2, whole(11)?)])?;
        (
            Objects::copy(&archive, &publisher)?,
            archive.pin(),
            archive.records().to_vec(),
        )
    };
    for digest in [
        records[0].pin.head,
        ContentDigest::sha256(&records[0].metadata()?),
        records[0].payload_digest,
    ] {
        let mut objects = objects.clone();
        let prefix = recover(&mut objects, pin)?;
        objects.bytes.remove(&digest);
        let mut replay = DatagramJpegReplay::new_detached(&prefix, spec(), bounds(), 0)?;
        let refusal = replay
            .step_detached(&mut objects, 1, &NeverCancel, &mut work())
            .err()
            .ok_or("missing current custody accepted")?;
        assert!(matches!(refusal.reason, JpegReplayError::Source(_)));
        assert_eq!(
            refusal
                .retirement
                .ok_or("lost retirement")?
                .observations_read,
            0
        );
        assert!(matches!(
            replay.step_detached(&mut objects, 1, &NeverCancel, &mut work())?,
            JpegReplayStep::Ended
        ));
    }
    Ok(())
}

#[test]
fn cancellation_after_detached_frame_keeps_bound_output_in_one_terminal_retirement() -> Test {
    struct Second(Cell<u32>);
    impl PublishCancellation for Second {
        fn cancel_requested(&self, _: PublishCutPoint) -> bool {
            self.0.set(self.0.get() + 1);
            self.0.get() >= 2
        }
    }
    let (mut objects, pin) = {
        let (_directory, publisher, archive) =
            published(&[(0, 1, whole(10)?), (0, 2, whole(11)?)])?;
        (Objects::copy(&archive, &publisher)?, archive.pin())
    };
    let prefix = recover(&mut objects, pin)?;
    let mut replay = DatagramJpegReplay::new_detached(&prefix, spec(), bounds(), 0)?;
    for _ in 0..2 {
        assert!(matches!(
            replay.step_detached(&mut objects, 1, &NeverCancel, &mut work())?,
            JpegReplayStep::Rtp { .. }
        ));
    }
    let failure = replay
        .step_detached(&mut objects, 1, &Second(Cell::new(0)), &mut work())
        .err()
        .ok_or("cancelled frame escaped")?;
    assert!(matches!(
        failure.reason,
        JpegReplayError::Source(DatagramArchiveError::Cancelled)
    ));
    let retirement = failure.retirement.ok_or("missing retirement")?;
    assert_eq!(retirement.observations_read, 2);
    let withheld = retirement.withheld.ok_or("lost frame")?;
    let (image, proof) = frame(&withheld).ok_or("lost bound provenance")?;
    assert_eq!(proof.encoded_digest(), ContentDigest::sha256(image.bytes()));
    assert!(replay.cancel().is_none());
    assert!(matches!(
        replay.step_detached(&mut objects, 1, &NeverCancel, &mut work())?,
        JpegReplayStep::Ended
    ));
    Ok(())
}

#[test]
fn detached_replay_retains_clock_deadline_step_and_work_refusals() -> Test {
    let (mut objects, pin) = {
        let (_directory, publisher, archive) = published(&[(0, 1, whole(10)?)])?;
        (Objects::copy(&archive, &publisher)?, archive.pin())
    };
    let prefix = recover(&mut objects, pin)?;
    assert!(
        DatagramJpegReplay::new_detached(
            &prefix,
            spec(),
            JpegReplayBounds {
                max_source_bytes: pin.payload_bytes - 1,
                ..bounds()
            },
            0
        )
        .is_err()
    );
    let mut replay = DatagramJpegReplay::new_detached(&prefix, spec(), bounds(), 10)?;
    let failure = replay
        .step_detached(&mut objects, 9, &NeverCancel, &mut work())
        .err()
        .ok_or("clock reversal accepted")?;
    assert!(matches!(failure.reason, JpegReplayError::ClockReversed));
    assert!(failure.retirement.is_none());
    assert_eq!(replay.observations_read(), 0);
    let failure = replay
        .step_detached(
            &mut objects,
            bounds().deadline_ns,
            &NeverCancel,
            &mut work(),
        )
        .err()
        .ok_or("deadline accepted")?;
    assert!(matches!(
        failure.reason,
        JpegReplayError::Source(DatagramArchiveError::Deadline)
    ));
    let mut replay = DatagramJpegReplay::new_detached(
        &prefix,
        spec(),
        JpegReplayBounds {
            max_steps: 1,
            ..bounds()
        },
        0,
    )?;
    assert!(matches!(
        replay.step_detached(&mut objects, 1, &NeverCancel, &mut work())?,
        JpegReplayStep::Rtp { .. }
    ));
    let failure = replay
        .step_detached(&mut objects, 1, &NeverCancel, &mut work())
        .err()
        .ok_or("step ceiling ignored")?;
    assert!(matches!(
        failure.reason,
        JpegReplayError::Source(DatagramArchiveError::Limit)
    ));
    let mut replay = DatagramJpegReplay::new_detached(&prefix, spec(), bounds(), 0)?;
    let failure = replay
        .step_detached(&mut objects, 1, &NeverCancel, &mut WorkBudget::new(1))
        .err()
        .ok_or("work ceiling ignored")?;
    assert!(matches!(
        failure.reason,
        JpegReplayError::Source(DatagramArchiveError::Work(_))
    ));
    assert_eq!(
        failure
            .retirement
            .ok_or("missing work retirement")?
            .observations_read,
        0
    );
    Ok(())
}

#[test]
fn exact_native_provenance_bytes_reject_another_frame_and_obey_whole_work_and_cancellation() -> Test
{
    let (mut objects, pin) = {
        let (_directory, publisher, archive) = published(&[
            (0, 10, quantized(10, true)?),
            (0, 11, quantized(11, true)?),
            (0, 12, quantized(12, false)?),
        ])?;
        (Objects::copy(&archive, &publisher)?, archive.pin())
    };
    let prefix = recover(&mut objects, pin)?;
    let steps = detached_steps(&prefix, &mut objects)?;
    let frames: Vec<_> = steps.iter().filter_map(frame).collect();
    assert_eq!(frames.len(), 2);
    let (image, proof) = frames[0];
    let mut measured = work();
    let bytes = proof.canonical_bytes(image, &mut measured)?;
    assert_eq!(ContentDigest::sha256(&bytes), proof.digest());
    let mut decoder = fss_core::CanonicalDecoder::new(&bytes);
    assert_eq!(
        decoder.text()?,
        "fss.rtsp_datagram_jpeg_frame_provenance.v1"
    );
    let consumed = measured.used();
    assert_eq!(
        proof.canonical_bytes(image, &mut WorkBudget::new(consumed))?,
        bytes
    );
    assert!(matches!(
        proof.canonical_bytes(image, &mut WorkBudget::new(consumed - 1)),
        Err(JpegReplayError::Source(DatagramArchiveError::Work(_)))
    ));
    assert_eq!(image.bytes(), frames[1].0.bytes());
    assert_ne!(image.timestamp(), frames[1].0.timestamp());
    assert!(matches!(
        proof.canonical_bytes(frames[1].0, &mut work()),
        Err(JpegReplayError::Invariant)
    ));
    let probes = std::sync::atomic::AtomicUsize::new(0);
    let late_cancel = || probes.fetch_add(1, std::sync::atomic::Ordering::Relaxed) > 0;
    let mut cancelled = WorkBudget::with_cancellation_probe(consumed, &late_cancel);
    assert!(matches!(
        proof.canonical_bytes(image, &mut cancelled),
        Err(JpegReplayError::Source(DatagramArchiveError::Work(
            fss_geometry::GeometryError::Cancelled
        )))
    ));
    assert_eq!(cancelled.used(), consumed);
    Ok(())
}

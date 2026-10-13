#![forbid(unsafe_code)]
//! Real native pixels, original packet provenance, and bounded refusal behavior.
mod rtpdump_support;
use fss_codec_h264::{Decoder, DecoderLimits, Picture};
use fss_core::ContentDigest;
use fss_packet::avc::AvcReceiveLimits;
use fss_reference::ingest::rtpdump::avc::{AvcDumpConfig, AvcDumpStep};
use fss_reference::ingest::rtpdump::decode::{
    RecordedRtpH264Decoder, RtpDecodeEffect, RtpDecodeError, RtpDecodeLimits, RtpDecodeRecovery,
    RtpDecodeStep,
};
use fss_reference::ingest::rtpdump::{RtpDumpLimits, RtpDumpReader};
use rtpdump_support::*;

fn settings() -> AvcDumpConfig {
    let c = config_for(7);
    AvcDumpConfig {
        key: c.key,
        payload_type: c.payload_type,
        mode: c.mode,
        dump: c.dump,
        receiver: AvcReceiveLimits::default(),
        rtcp: c.rtcp,
    }
}
fn open(bytes: &[u8], limits: RtpDecodeLimits) -> Result<RecordedRtpH264Decoder<'_>, Error> {
    let all = nals();
    let sps = all.iter().find(|n| n[0] & 31 == 7).ok_or("SPS")?;
    let pps = all.iter().find(|n| n[0] & 31 == 8).ok_or("PPS")?;
    Ok(RecordedRtpH264Decoder::new(
        bytes,
        settings(),
        sps,
        pps,
        limits,
    )?)
}
fn digest(p: &Picture) -> ContentDigest {
    ContentDigest::sha256(&[p.luma(), p.cb(), p.cr()].concat())
}
fn expected() -> Result<Vec<ContentDigest>, Error> {
    let mut decoder = Decoder::new(DecoderLimits::default())?;
    let mut frames = Vec::new();
    for nal in nals() {
        if let Some(p) = decoder.decode_nal(nal)? {
            frames.push(digest(&p));
        }
        while let Some(p) = decoder.next_output() {
            frames.push(digest(&p));
        }
    }
    frames.extend(decoder.finish()?.iter().map(digest));
    assert_eq!(frames.len(), 4);
    Ok(frames)
}
fn records(bytes: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut reader = RtpDumpReader::new(bytes, RtpDumpLimits::default())?;
    let mut out = Vec::new();
    while let Some(record) = reader.next_record()? {
        out.push(bytes[record.span()].to_vec());
    }
    Ok(out)
}
fn join(records: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = header();
    for record in records {
        bytes.extend_from_slice(record);
    }
    bytes
}
fn clean(bytes: &[u8]) -> Result<Vec<ContentDigest>, Error> {
    let cx = cx()?;
    let mut replay = open(bytes, RtpDecodeLimits::default())?;
    let mut pixels = Vec::new();
    let mut originals = 0;
    let mut finished = false;
    let mut exhausted = false;
    for _ in 0..10_000 {
        match replay.step(&cx) {
            RtpDecodeStep::Replay { event, effect } => {
                if let AvcDumpStep::Record { source, .. } = event {
                    assert_eq!(source.index(), originals);
                    assert_eq!(source.packet(), &bytes[source.packet_span()]);
                    originals += 1;
                }
                match effect {
                    RtpDecodeEffect::Refused { error, .. } => return Err(error.into()),
                    RtpDecodeEffect::Finished => finished = true,
                    RtpDecodeEffect::WaitingForIdr { .. } => {
                        return Err("unexpected skipped picture".into());
                    }
                    _ => {}
                }
            }
            RtpDecodeStep::Picture(frame) => {
                let source = frame.source();
                assert_eq!(source.recording, ContentDigest::sha256(bytes));
                assert_eq!(source.key, settings().key);
                assert!(!source.nals.is_empty());
                for nal in &source.nals {
                    let len = nal
                        .spans
                        .iter()
                        .map(|s| s.nal.end)
                        .max()
                        .ok_or("empty map")?;
                    let mut reconstructed = vec![0; len];
                    for span in &nal.spans {
                        // Original admission must precede every derived pixel event.
                        assert!(span.record < originals);
                        reconstructed[span.nal.clone()].copy_from_slice(&bytes[span.wire.clone()]);
                        if let Some(range) = &span.fragment_header {
                            let h = &bytes[range.clone()];
                            assert_eq!(h.len(), 2);
                            reconstructed[0] = (h[0] & 0xe0) | (h[1] & 31);
                        }
                    }
                    assert_eq!(ContentDigest::sha256(&reconstructed), nal.digest);
                }
                pixels.push(digest(frame.picture()));
            }
            RtpDecodeStep::Exhausted => {
                exhausted = true;
                break;
            }
        }
    }
    assert!(exhausted && finished);
    assert_eq!(originals, records(bytes)?.len());
    Ok(pixels)
}

#[test]
fn single_nal_and_fragmented_recordings_decode_native_pixels_with_exact_source_spans() -> TestResult
{
    let expected = expected()?;
    for fragmented in [false, true] {
        assert_eq!(clean(&real_dump(fragmented))?, expected);
    }
    Ok(())
}

#[test]
fn reordered_fu_start_and_end_recover_all_pixels_across_sequence_wrap() -> TestResult {
    let mut packets = records(&real_dump(true))?;
    let first = packets
        .iter()
        .position(|r| r.len() > 21 && r[20] & 31 == 28 && r[21] & 128 != 0)
        .ok_or("FU start")?;
    packets.swap(first, first + 1);
    assert_eq!(clean(&join(&packets))?, expected()?);
    Ok(())
}

#[test]
fn duplicate_datagrams_do_not_duplicate_frames_or_rewrite_first_source() -> TestResult {
    let mut packets = records(&real_dump(true))?;
    let last = packets.last().ok_or("last")?.clone();
    packets.push(last.clone());
    packets.push(last);
    assert_eq!(clean(&join(&packets))?, expected()?);
    Ok(())
}

#[test]
fn incomplete_fragment_fences_decode_without_hiding_following_originals() -> TestResult {
    let mut planned = packetize(2, 100, 65534, 7, 90000, 0);
    let missing = planned.iter().position(|p| p.vcl).ok_or("VCL packet")?;
    planned.remove(missing);
    let bytes = dump_planned(&planned);
    let cx = cx()?;
    let mut replay = open(
        &bytes,
        RtpDecodeLimits {
            recovery: RtpDecodeRecovery::Stop,
            ..RtpDecodeLimits::default()
        },
    )?;
    let mut originals = 0;
    let mut fenced = false;
    let mut exhausted = false;
    for _ in 0..10_000 {
        match replay.step(&cx) {
            RtpDecodeStep::Replay { event, effect } => {
                if matches!(event, AvcDumpStep::Record { .. }) {
                    originals += 1;
                }
                if matches!(effect, RtpDecodeEffect::Refused { .. }) {
                    fenced = true;
                }
            }
            RtpDecodeStep::Picture(_) => {
                assert!(!fenced, "pixels crossed the failed reference chain");
            }
            RtpDecodeStep::Exhausted => {
                exhausted = true;
                break;
            }
        }
    }
    assert!(exhausted && fenced);
    assert_eq!(originals, planned.len());
    Ok(())
}

#[test]
fn output_budget_refusal_keeps_every_original_and_never_returns_over_budget_pixels() -> TestResult {
    let bytes = real_dump(true);
    let cx = cx()?;
    let mut replay = open(
        &bytes,
        RtpDecodeLimits {
            max_output_bytes: 1,
            ..RtpDecodeLimits::default()
        },
    )?;
    let mut originals = 0;
    let mut limited = false;
    let mut exhausted = false;
    for _ in 0..10_000 {
        match replay.step(&cx) {
            RtpDecodeStep::Replay { event, effect } => {
                if matches!(event, AvcDumpStep::Record { .. }) {
                    originals += 1;
                }
                limited |= matches!(
                    effect,
                    RtpDecodeEffect::Refused {
                        error: RtpDecodeError::Limit,
                        ..
                    }
                );
            }
            RtpDecodeStep::Picture(_) => return Err("over-budget frame escaped".into()),
            RtpDecodeStep::Exhausted => {
                exhausted = true;
                break;
            }
        }
    }
    assert!(exhausted && limited);
    assert_eq!(originals, records(&bytes)?.len());
    Ok(())
}

#[test]
fn malformed_tail_is_not_clean_decode_completion() -> TestResult {
    let mut bytes = real_dump(false);
    bytes.extend_from_slice(&[0, 10, 0]);
    let cx = cx()?;
    let mut replay = open(&bytes, RtpDecodeLimits::default())?;
    let mut refused = false;
    let mut exhausted = false;
    for _ in 0..10_000 {
        match replay.step(&cx) {
            RtpDecodeStep::Replay { event, effect } => {
                refused |= matches!(event, AvcDumpStep::FramingRefused { .. });
                assert!(!matches!(effect, RtpDecodeEffect::Finished));
            }
            RtpDecodeStep::Exhausted => {
                exhausted = true;
                break;
            }
            _ => {}
        }
    }
    assert!(exhausted && refused);
    Ok(())
}

#[test]
fn missing_reference_chain_resumes_only_at_a_fresh_idr_with_exact_native_pixels() -> TestResult {
    let mut planned = packetize(2, 100, 65534, 7, 90000, 0);
    let missing = planned
        .iter()
        .position(|p| p.vcl)
        .ok_or("first IDR packet")?;
    planned.remove(missing);
    let bytes = dump_planned(&planned);
    let cx = cx()?;
    let mut replay = open(&bytes, RtpDecodeLimits::default())?;
    let mut originals = 0;
    let mut gaps = 0;
    let mut waiting = 0;
    let mut frames = Vec::new();
    let mut exhausted = false;
    // The retained fixture is IDR/P/P/IDR (keyint=3). Its final IDR is already a
    // valid recovery point, before the second copy of the four-picture fixture.
    // Pin exact source timestamps and all five surviving native pictures.
    let original_pixels = expected()?;
    let recovered_pixels: Vec<_> = original_pixels[3..]
        .iter()
        .chain(&original_pixels)
        .copied()
        .collect();
    for _ in 0..10_000 {
        match replay.step(&cx) {
            RtpDecodeStep::Replay { event, effect } => {
                if matches!(event, AvcDumpStep::Record { .. }) {
                    originals += 1;
                }
                match effect {
                    RtpDecodeEffect::Refused {
                        awaiting_idr: true, ..
                    } => gaps += 1,
                    RtpDecodeEffect::Refused { error, .. } => return Err(error.into()),
                    RtpDecodeEffect::WaitingForIdr { .. } => waiting += 1,
                    _ => {}
                }
            }
            RtpDecodeStep::Picture(frame) => {
                assert_eq!(frame.source().key, settings().key);
                assert_eq!(frame.source().decoder_epoch, 1);
                assert_eq!(
                    frame.source().timestamp,
                    90000 + (3 + frames.len() as u32) * 3600
                );
                if frames.is_empty() {
                    assert!(frame.picture().is_idr());
                }
                frames.push(digest(frame.picture()));
            }
            RtpDecodeStep::Exhausted => {
                exhausted = true;
                break;
            }
        }
    }
    assert!(exhausted);
    assert!(gaps > 0 && waiting > 0);
    assert_eq!(originals, planned.len());
    assert_eq!(frames, recovered_pixels);
    Ok(())
}

#[test]
fn decoder_picture_budget_is_not_replenished_by_idr_recovery() -> TestResult {
    let mut planned = packetize(2, 100, 65534, 7, 90000, 0);
    // Preserve the first IDR, then damage its first dependent picture.
    let missing = planned
        .iter()
        .position(|p| p.timestamp == 93600 && p.vcl)
        .ok_or("P packet")?;
    planned.remove(missing);
    let bytes = dump_planned(&planned);
    let cx = cx()?;
    let limits = RtpDecodeLimits {
        codec: DecoderLimits {
            max_pictures: 2,
            ..DecoderLimits::default()
        },
        ..RtpDecodeLimits::default()
    };
    let mut replay = open(&bytes, limits)?;
    let mut count = 0;
    let mut limited = false;
    let mut recovered = false;
    let mut damaged = false;
    let mut originals = 0;
    let mut exhausted = false;
    for _ in 0..10_000 {
        match replay.step(&cx) {
            RtpDecodeStep::Replay { event, effect } => {
                if matches!(event, AvcDumpStep::Record { .. }) {
                    originals += 1;
                }
                limited |= matches!(
                    effect,
                    RtpDecodeEffect::Refused {
                        error: RtpDecodeError::Limit,
                        ..
                    }
                );
                damaged |= matches!(
                    effect,
                    RtpDecodeEffect::Refused {
                        awaiting_idr: true,
                        ..
                    }
                );
                recovered |= damaged && matches!(effect, RtpDecodeEffect::Admitted { .. });
            }
            RtpDecodeStep::Picture(frame) => {
                assert!(!limited);
                recovered |= frame.source().decoder_epoch > 0;
                count += 1;
            }
            RtpDecodeStep::Exhausted => {
                exhausted = true;
                break;
            }
        }
    }
    assert!(exhausted && limited);
    assert!(count <= 2);
    // Delayed output or retirement of an accepted picture cannot refund its admission.
    assert!(damaged && recovered);
    assert_eq!(originals, planned.len());
    Ok(())
}

#[test]
fn cancellation_retires_queued_pixels_before_delivery() -> TestResult {
    let bytes = real_dump(false);
    let cx = cx()?;
    let mut replay = open(&bytes, RtpDecodeLimits::default())?;
    for _ in 0..10_000 {
        let _ = replay.step(&cx);
        if replay.queued_pictures() > 0 {
            break;
        }
    }
    assert!(replay.queued_pictures() > 0);
    cx.request_cancellation();
    assert!(!matches!(replay.step(&cx), RtpDecodeStep::Picture(_)));
    assert_eq!(replay.queued_pictures(), 0);
    assert!(matches!(replay.step(&cx), RtpDecodeStep::Exhausted));
    assert!(cx.is_drain_completed());
    Ok(())
}

#[test]
fn cancellation_after_eof_flush_still_reports_queued_pixel_retirement() -> TestResult {
    let bytes = real_dump(false);
    let cx = cx()?;
    let mut replay = open(&bytes, RtpDecodeLimits::default())?;
    let mut finished = false;
    for _ in 0..10_000 {
        if matches!(
            replay.step(&cx),
            RtpDecodeStep::Replay {
                effect: RtpDecodeEffect::Finished,
                ..
            }
        ) {
            finished = true;
            break;
        }
    }
    assert!(finished);
    let queued = replay.queued_pictures();
    cx.request_cancellation();
    match replay.step(&cx) {
        RtpDecodeStep::Replay {
            effect:
                RtpDecodeEffect::Refused {
                    error: RtpDecodeError::Cancelled,
                    retired_groups,
                    awaiting_idr: false,
                    ..
                },
            ..
        } => assert_eq!(retired_groups, queued),
        other => return Err(format!("lost cancellation retirement: {other:?}").into()),
    }
    assert_eq!(replay.queued_pictures(), 0);
    assert!(matches!(replay.step(&cx), RtpDecodeStep::Exhausted));
    Ok(())
}

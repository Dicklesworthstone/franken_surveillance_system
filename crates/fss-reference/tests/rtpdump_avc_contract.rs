#![forbid(unsafe_code)]
//! Recorded rtpdump AVC streams into source-mapped picture groups under reordering, duplicates and EOF.
mod rtpdump_support;
use fss_packet::avc::{
    AvcAssemblyStep, AvcBoundary, AvcPictureGroup, AvcPps, AvcReceiveLimits, AvcReceivePoll,
    AvcSps, parse_pps, parse_sps,
};
use fss_reference::ingest::rtpdump::{RtpDumpLimits, RtpDumpReader, avc::*};
use rtpdump_support::*;

fn settings() -> Result<(AvcDumpConfig, (AvcSps, AvcPps)), Error> {
    let c = config();
    let limits = AvcReceiveLimits::default();
    let all = nals();
    let sps = parse_sps(
        all.iter().find(|n| n[0] & 31 == 7).ok_or("SPS")?,
        limits.syntax,
    )?;
    let pps = parse_pps(
        all.iter().find(|n| n[0] & 31 == 8).ok_or("PPS")?,
        &sps,
        limits.syntax,
    )?;
    Ok((
        AvcDumpConfig {
            key: c.key,
            payload_type: c.payload_type,
            mode: c.mode,
            dump: c.dump,
            receiver: limits,
            rtcp: c.rtcp,
        },
        (sps, pps),
    ))
}
fn picture(event: &AvcReceivePoll) -> Option<&AvcPictureGroup> {
    match event {
        AvcReceivePoll::Picture(p) => Some(p),
        AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(output)) => output.picture.as_ref(),
        AvcReceivePoll::Ended {
            tail: Some(output), ..
        } => output.picture.as_ref(),
        _ => None,
    }
}
fn chunks(bytes: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut reader = RtpDumpReader::new(bytes, RtpDumpLimits::default())?;
    let mut out = Vec::new();
    while let Some(r) = reader.next_record()? {
        out.push(bytes[r.span()].to_vec());
    }
    Ok(out)
}
fn join(records: Vec<Vec<u8>>) -> Vec<u8> {
    let mut b = header();
    for r in records {
        b.extend_from_slice(&r);
    }
    b
}

#[test]
fn real_recorded_single_and_fu_streams_produce_four_source_mapped_picture_groups() -> TestResult {
    for fragmented in [false, true] {
        let bytes = real_dump(fragmented);
        let cx = cx()?;
        let (cfg, params) = settings()?;
        let mut replay = RecordedAvcReplay::new(&bytes, cfg, params)?;
        let mut groups = 0;
        let mut records = 0;
        let mut ended = false;
        for _ in 0..1000 {
            match replay.step(&cx) {
                AvcDumpStep::Record {
                    source,
                    admission: AvcDumpAdmission::Rtp(_),
                    ..
                } => {
                    assert_eq!(source.packet(), &bytes[source.packet_span()]);
                    records += 1;
                }
                AvcDumpStep::Progress(event) => {
                    if let Some(group) = picture(&event) {
                        groups += 1;
                        assert!(group.saw_first_macroblock());
                        assert_eq!(group.boundary(), AvcBoundary::RtpMarker);
                        for nal in group.nals() {
                            let mapped = replay.map_nal(nal)?;
                            assert!(!mapped.is_empty());
                            for span in mapped {
                                assert_eq!(&bytes[span.wire], &nal.bytes()[span.nal]);
                            }
                        }
                    }
                    if let AvcReceivePoll::Source { source, .. } = &event {
                        let original = replay
                            .source_record(source.sequence())
                            .ok_or("source map")?;
                        assert_eq!(source.bytes(), original.packet());
                    }
                    if matches!(event, AvcReceivePoll::Ended { .. }) {
                        ended = true;
                    }
                    assert!(!matches!(
                        event,
                        AvcReceivePoll::Assembly(AvcAssemblyStep::Refused(_))
                    ));
                }
                AvcDumpStep::InputEnded => {}
                AvcDumpStep::Exhausted => break,
                other => return Err(format!("unexpected {other:?}").into()),
            }
        }
        assert_eq!(records, chunks(&bytes)?.len());
        assert_eq!(groups, 4);
        assert!(ended);
        assert_eq!(replay.retained_nal_bytes(), 0);
    }
    Ok(())
}

#[test]
fn bounded_reordering_recovers_fragments_before_their_deadline_without_remapping_sources()
-> TestResult {
    let original = real_dump(true);
    let mut records = chunks(&original)?;
    // Each record has 8 container bytes and a 12-byte RTP header. Exchange the
    // first FU start/end, keeping the originals (including recorder offsets).
    let start = records
        .iter()
        .position(|r| r.len() > 21 && r[20] & 31 == 28 && r[21] & 128 != 0)
        .ok_or("FU start")?;
    records.swap(start, start + 1);
    let bytes = join(records);
    let cx = cx()?;
    let (cfg, params) = settings()?;
    let mut replay = RecordedAvcReplay::new(&bytes, cfg, params)?;
    let mut groups = 0;
    for _ in 0..1000 {
        match replay.step(&cx) {
            AvcDumpStep::Progress(event) => {
                if let Some(group) = picture(&event) {
                    groups += 1;
                    for n in group.nals() {
                        assert!(!replay.map_nal(n)?.is_empty());
                    }
                }
                assert!(!matches!(
                    event,
                    AvcReceivePoll::Gap { .. } | AvcReceivePoll::CodecRefused { .. }
                ));
            }
            AvcDumpStep::Record {
                admission: AvcDumpAdmission::Rtp(_),
                ..
            }
            | AvcDumpStep::InputEnded => {}
            AvcDumpStep::Exhausted => break,
            other => return Err(format!("unexpected {other:?}").into()),
        }
    }
    assert_eq!(groups, 4);
    Ok(())
}

#[test]
fn duplicate_record_does_not_duplicate_a_picture_or_replace_first_source_mapping() -> TestResult {
    let original = real_dump(false);
    let mut records = chunks(&original)?;
    let repeat = records.last().ok_or("record")?.clone();
    records.push(repeat);
    let bytes = join(records);
    let cx = cx()?;
    let (cfg, params) = settings()?;
    let mut replay = RecordedAvcReplay::new(&bytes, cfg, params)?;
    let mut groups = 0;
    for _ in 0..1000 {
        match replay.step(&cx) {
            AvcDumpStep::Progress(event) => {
                if picture(&event).is_some() {
                    groups += 1;
                }
            }
            AvcDumpStep::Exhausted => break,
            _ => {}
        }
    }
    assert_eq!(groups, 4);
    Ok(())
}

#[test]
fn eof_with_unfinished_fu_retires_derivatives_instead_of_publishing_a_fourth_picture() -> TestResult
{
    let mut records = chunks(&real_dump(true))?;
    let removed = records.pop().ok_or("last")?;
    assert_eq!(removed[20] & 31, 28);
    assert_ne!(removed[21] & 64, 0);
    let bytes = join(records);
    let cx = cx()?;
    let (cfg, params) = settings()?;
    let mut replay = RecordedAvcReplay::new(&bytes, cfg, params)?;
    let mut groups = 0;
    let mut retired = false;
    for _ in 0..1000 {
        match replay.step(&cx) {
            AvcDumpStep::Progress(event) => {
                if picture(&event).is_some() {
                    groups += 1;
                }
                if matches!(
                    event,
                    AvcReceivePoll::Ended {
                        fragment: Some(_),
                        ..
                    }
                ) {
                    retired = true;
                }
            }
            AvcDumpStep::Exhausted => break,
            _ => {}
        }
    }
    assert_eq!(groups, 3);
    assert!(retired);
    assert_eq!(replay.retained_nal_bytes(), 0);
    Ok(())
}

#[test]
fn capture_limited_record_fences_media_but_keeps_following_originals_visible() -> TestResult {
    let original = real_dump(true);
    let mut records = chunks(&original)?;
    let start = records
        .iter()
        .position(|r| r.len() > 21 && r[20] & 31 == 28)
        .ok_or("FU")?;
    let length = u16::from_be_bytes([records[start][2], records[start][3]]);
    records[start][2..4].copy_from_slice(&(length + 1).to_be_bytes());
    let bytes = join(records);
    let cx = cx()?;
    let (cfg, params) = settings()?;
    let mut replay = RecordedAvcReplay::new(&bytes, cfg, params)?;
    let mut prefix = false;
    let mut following = 0;
    for _ in 0..1000 {
        match replay.step(&cx) {
            AvcDumpStep::Record {
                source, admission, ..
            } => {
                assert_eq!(source.packet(), &bytes[source.packet_span()]);
                match admission {
                    AvcDumpAdmission::CapturedPrefix(_) => prefix = true,
                    AvcDumpAdmission::Fenced => {
                        assert!(prefix);
                        following += 1;
                    }
                    _ => {}
                }
            }
            AvcDumpStep::Progress(event) => {
                if prefix {
                    assert!(picture(&event).is_none());
                }
            }
            AvcDumpStep::Exhausted => break,
            _ => {}
        }
    }
    assert!(prefix);
    assert!(following > 0);
    assert_eq!(replay.retained_nal_bytes(), 0);
    Ok(())
}

#[test]
fn malformed_tail_is_not_a_clean_eof_and_cancellation_retires_pending_work() -> TestResult {
    let mut bytes = real_dump(false);
    bytes.extend_from_slice(&[0, 20, 0, 12]);
    let cx = cx()?;
    let (cfg, params) = settings()?;
    let mut replay = RecordedAvcReplay::new(&bytes, cfg, params)?;
    let mut refused = false;
    for _ in 0..1000 {
        match replay.step(&cx) {
            AvcDumpStep::FramingRefused { .. } => {
                refused = true;
                break;
            }
            AvcDumpStep::InputEnded => return Err("bad framing became clean EOF".into()),
            _ => {}
        }
    }
    assert!(refused);
    assert!(matches!(replay.step(&cx), AvcDumpStep::Exhausted));
    let bytes = real_dump(true);
    let (cfg, params) = settings()?;
    let mut replay = RecordedAvcReplay::new(&bytes, cfg, params)?;
    for _ in 0..1000 {
        let _ = replay.step(&cx);
        if replay.retained_nal_bytes() > 0 {
            break;
        }
    }
    assert!(replay.retained_nal_bytes() > 0);
    cx.request_cancellation();
    assert!(matches!(replay.step(&cx), AvcDumpStep::Cancelled(_)));
    assert_eq!(replay.retained_nal_bytes(), 0);
    assert!(cx.is_drain_completed());
    Ok(())
}

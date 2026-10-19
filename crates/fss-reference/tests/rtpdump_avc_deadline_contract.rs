#![forbid(unsafe_code)]
//! Sparse recordings must run receiver deadlines, not lend late fragments a new lifetime.
mod rtpdump_support;

use fss_packet::H264Error;
use fss_packet::avc::{AvcAssemblyStep, AvcPps, AvcReceiveLimits, AvcReceivePoll, AvcSps};
use fss_packet::avc::{parse_pps, parse_sps};
use fss_reference::ingest::rtpdump::avc::*;
use rtpdump_support::*;

fn settings() -> Result<(AvcDumpConfig, (AvcSps, AvcPps)), Error> {
    let c = config();
    let mut limits = AvcReceiveLimits::default();
    limits.reorder.max_delay_ns = 10_000_000;
    limits.reconstruction.max_pending_age_ns = 20_000_000;
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

fn sparse_fragment_dump(tail_ms: u32) -> Result<Vec<u8>, Error> {
    let all = nals();
    let nal = all.iter().find(|n| n[0] & 31 == 5).ok_or("IDR")?;
    let mid = 1 + (nal.len() - 1) / 2;
    let mut start = vec![(nal[0] & 0x60) | 28, (nal[0] & 31) | 128];
    start.extend_from_slice(&nal[1..mid]);
    let mut end = vec![(nal[0] & 0x60) | 28, (nal[0] & 31) | 64];
    end.extend_from_slice(&nal[mid..]);
    // 10 establishes probation, 11 validates it, and 12 is missing. The FU
    // start queued at 1 ms must be delivered at the 11 ms reorder deadline.
    // Its independent reconstruction deadline is therefore 31 ms, not tail_ms + 20.
    Ok(dump(&[
        (10, false, &[0x09, 0xf0], 0),
        (11, false, &[0x09, 0xf0], 0),
        (13, false, &start, 1),
        (14, true, &end, tail_ms),
    ]))
}

#[test]
fn sparse_arrival_visits_reorder_then_fragment_deadline_before_admitting_tail() -> TestResult {
    for (tail_ms, should_expire) in [(30, false), (31, true), (100, true), (u32::MAX, true)] {
        let bytes = sparse_fragment_dump(tail_ms)?;
        let cx = cx()?;
        let (cfg, params) = settings()?;
        let mut replay = RecordedAvcReplay::new(&bytes, cfg, params)?;
        let mut records = 0;
        let mut gaps = 0;
        let mut expired = 0;
        let mut pictures = 0;
        let mut exhausted = false;
        for _ in 0..128 {
            match replay.step(&cx) {
                AvcDumpStep::Record {
                    source,
                    admission: AvcDumpAdmission::Rtp(_),
                    ..
                } => {
                    assert_eq!(source.packet(), &bytes[source.packet_span()]);
                    records += 1;
                    if records == 4 {
                        assert_eq!(expired > 0, should_expire, "tail offset {tail_ms}");
                    }
                }
                AvcDumpStep::Progress(event) => {
                    match &event {
                        AvcReceivePoll::Gap { .. } => gaps += 1,
                        AvcReceivePoll::FragmentRetired { fragment, .. } => {
                            assert_eq!(fragment.reason, H264Error::Deadline);
                            assert_eq!(fragment.first_sequence, 13);
                            assert_eq!(fragment.last_sequence, 13);
                            assert_eq!(records, 3, "expiry must precede the late original");
                            expired += 1;
                        }
                        _ => {}
                    }
                    let group = match &event {
                        AvcReceivePoll::Picture(p) => Some(p),
                        AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(o)) => {
                            o.picture.as_ref()
                        }
                        AvcReceivePoll::Ended { tail: Some(o), .. } => o.picture.as_ref(),
                        _ => None,
                    };
                    if let Some(group) = group {
                        pictures += 1;
                        for nal in group.nals() {
                            for span in replay.map_nal(nal)? {
                                assert_eq!(&bytes[span.wire], &nal.bytes()[span.nal]);
                            }
                        }
                    }
                }
                AvcDumpStep::InputEnded => {}
                AvcDumpStep::Exhausted => {
                    exhausted = true;
                    break;
                }
                other => return Err(format!("unexpected replay event: {other:?}").into()),
            }
        }
        assert!(
            exhausted,
            "large source offsets must not cause timer spinning"
        );
        assert_eq!(records, 4);
        assert_eq!(gaps, 1);
        assert_eq!(expired, usize::from(should_expire));
        assert_eq!(pictures, usize::from(!should_expire));
        assert_eq!(replay.retained_nal_bytes(), 0);
    }
    Ok(())
}

#[test]
fn cancellation_between_deadline_events_does_not_admit_the_pending_original() -> TestResult {
    let bytes = sparse_fragment_dump(100)?;
    let cx = cx()?;
    let (cfg, params) = settings()?;
    let mut replay = RecordedAvcReplay::new(&bytes, cfg, params)?;
    let mut records = 0;
    for _ in 0..128 {
        match replay.step(&cx) {
            AvcDumpStep::Record { .. } => records += 1,
            AvcDumpStep::Progress(AvcReceivePoll::Gap { .. }) => {
                assert_eq!(records, 3);
                cx.request_cancellation();
                assert!(matches!(replay.step(&cx), AvcDumpStep::Cancelled(_)));
                assert_eq!(replay.retained_nal_bytes(), 0);
                assert!(replay.source_record(14).is_none());
                assert!(replay.source_record(13).is_some());
                assert!(matches!(replay.step(&cx), AvcDumpStep::Exhausted));
                assert!(cx.is_drain_completed());
                return Ok(());
            }
            _ => {}
        }
    }
    Err("recorded reorder deadline did not fire".into())
}

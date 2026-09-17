#![forbid(unsafe_code)]
//! Deterministic receiver rehearsal: wrap, reordering, duplicate, loss, timer wake, cancellation.
//! Run: cargo run --locked -p fss-packet --example h264_packet_replay

use fss_core::ContentDigest;
use fss_packet::{
    FragmentDiscard, H264Error, H264Limits, H264Mode, H264ReceiveError, H264ReceivePoll,
    H264Receiver, ReorderLimits, StreamKey,
};

#[derive(Default)]
struct Counts {
    complete: usize,
    failures: usize,
    gaps: usize,
}

fn print_discard(discard: &FragmentDiscard) {
    println!(
        "{{\"kind\":\"discard\",\"ingress\":1,\"generation\":1,\"reason\":\"{:?}\",\"first_sequence\":{},\"last_sequence\":{},\"bytes\":{}}}",
        discard.reason, discard.first_sequence, discard.last_sequence, discard.byte_len
    );
}

fn drain(
    receiver: &mut H264Receiver,
    now_ns: u64,
    counts: &mut Counts,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        match receiver.poll(now_ns)? {
            H264ReceivePoll::Packet {
                source,
                reconstruction,
            } => {
                let extended = source.sequence();
                let digest = ContentDigest::try_sha256(source.bytes())?.to_text();
                println!(
                    "{{\"kind\":\"ordered_packet\",\"sequence\":{extended},\"digest\":\"{digest}\",\"received_ns\":{},\"delivered_ns\":{now_ns}}}",
                    source.received_ns()
                );
                match reconstruction {
                    Ok(output) => {
                        if let Some(discard) = output.discarded {
                            print_discard(&discard);
                        }
                        for nal in output.nals {
                            counts.complete += 1;
                            let digest = ContentDigest::try_sha256(nal.bytes())?.to_text();
                            println!(
                                "{{\"kind\":\"nal\",\"ingress\":1,\"generation\":1,\"sequence\":{extended},\"digest\":\"{digest}\",\"bytes\":{},\"source_spans\":{},\"nal_type\":{},\"marker\":{}}}",
                                nal.bytes().len(),
                                nal.sources().len(),
                                nal.nal_type(),
                                nal.marker()
                            );
                            if nal.nal_type() == 5 {
                                assert_eq!(nal.bytes(), &[0x65, 10, 20, 30]);
                                assert_eq!(nal.sources().len(), 3);
                            }
                        }
                    }
                    Err(H264ReceiveError::Codec(failure)) => {
                        counts.failures += 1;
                        assert_eq!(failure.reason, H264Error::MissingStart);
                        assert!(failure.discarded.is_none());
                        println!(
                            "{{\"kind\":\"codec_refusal\",\"sequence\":{extended},\"reason\":\"MissingStart\",\"source_digest\":\"{digest}\"}}"
                        );
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            H264ReceivePoll::Gap { gap, discarded } => {
                counts.gaps += 1;
                assert_eq!((gap.first_sequence, gap.last_sequence), (65_539, 65_539));
                let discard = discarded.ok_or("loss must retire the partial NAL")?;
                assert_eq!(discard.reason, H264Error::Gap);
                print_discard(&discard);
                println!(
                    "{{\"kind\":\"delivery_gap\",\"first_sequence\":{},\"last_sequence\":{},\"reason\":\"{:?}\"}}",
                    gap.first_sequence, gap.last_sequence, gap.reason
                );
            }
            H264ReceivePoll::FragmentDiscarded(discard) => print_discard(&discard),
            H264ReceivePoll::Pending { .. } => return Ok(()),
            H264ReceivePoll::Ended { .. } => return Err("unexpected early end".into()),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = StreamKey {
        ingress: 1,
        generation: 1,
        ssrc: 7,
    };
    let mut receiver = H264Receiver::new(
        key,
        96,
        H264Mode::NonInterleaved,
        ReorderLimits {
            max_delay_ns: 3_000_000,
            ..ReorderLimits::default()
        },
        H264Limits::default(),
    )?;
    let mut counts = Counts::default();
    for (ordinal, (seq, marker, payload)) in [
        (65_533_u16, false, vec![0x67, 0]),
        (65_534, false, vec![0x67, 1]),
        (65_535, false, vec![0x7c, 0x85, 10]),
        (1, true, vec![0x7c, 0x45, 30]),
        (1, true, vec![0x7c, 0x45, 30]),
        (0, false, vec![0x7c, 0x05, 20]),
        (2, false, vec![0x7c, 0x85, 40]),
        (4, true, vec![0x7c, 0x45, 50]),
        (5, true, vec![0x61, 60]),
        (6, false, vec![0x7c, 0x85, 70]),
    ]
    .into_iter()
    .enumerate()
    {
        let now_ns = ordinal as u64 * 1_000_000;
        let mut bytes = vec![0x80, 96 | if marker { 128 } else { 0 }];
        bytes.extend_from_slice(&seq.to_be_bytes());
        bytes.extend_from_slice(&90_000_u32.to_be_bytes());
        bytes.extend_from_slice(&key.ssrc.to_be_bytes());
        bytes.extend_from_slice(&payload);
        // Hash original input independently, including probation, duplicates, and refusals.
        let digest = ContentDigest::try_sha256(&bytes)?.to_text();
        let admission = receiver.ingest(key, &bytes, now_ns)?;
        println!(
            "{{\"kind\":\"packet\",\"fixture\":\"rtp-h264-reorder-wrap-v2\",\"ingress\":1,\"generation\":1,\"ssrc\":7,\"ordinal\":{ordinal},\"sequence\":{seq},\"digest\":\"{digest}\",\"class\":\"{:?}\",\"disposition\":\"{:?}\",\"missing\":{}}}",
            admission.transport.sequence.class,
            admission.transport.disposition,
            admission.transport.sequence.stats.missing
        );
        drain(&mut receiver, now_ns, &mut counts)?;
    }
    // Drive the advertised loss deadline without fabricating a new network packet.
    let wake = receiver
        .next_wake_ns()
        .ok_or("loss must provide a timer wake")?;
    assert_eq!(wake, 10_000_000);
    drain(&mut receiver, wake, &mut counts)?;
    let cancelled = receiver.cancel();
    let discard = cancelled
        .fragment
        .ok_or("final fragment must be cancelled")?;
    assert_eq!(discard.reason, H264Error::Cancelled);
    assert_eq!(cancelled.queue.packets, 0);
    assert_eq!(receiver.pending_nal_bytes(), 0);
    assert_eq!((counts.complete, counts.failures, counts.gaps), (3, 1, 1));
    assert_eq!(receiver.stats().missing, 1);
    print_discard(&discard);
    println!(
        "{{\"kind\":\"terminal\",\"ingress\":1,\"generation\":1,\"complete_nals\":{},\"safe_failures\":{},\"delivery_gaps\":{},\"missing\":1,\"cancelled_bytes\":{},\"pending_bytes\":0,\"qualification\":\"reference_rehearsal_only\"}}",
        counts.complete, counts.failures, counts.gaps, discard.byte_len
    );
    Ok(())
}

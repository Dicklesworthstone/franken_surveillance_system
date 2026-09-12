#![forbid(unsafe_code)]
//! Deterministic wire-to-NAL rehearsal: wrap, duplicate, gap, recovery, cancellation.
//! Run: cargo run --locked -p fss-packet --example h264_packet_replay

use fss_core::ContentDigest;
use fss_packet::{
    H264Depacketizer, H264Error, H264Limits, H264Mode, PacketLimits, RtpPacket,
    SequenceTracker, StreamKey,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = StreamKey { ingress: 1, generation: 1, ssrc: 7 };
    let mut sequence = SequenceTracker::new(key, 96)?;
    let mut media = H264Depacketizer::new(key, 96, H264Mode::NonInterleaved, H264Limits::default())?;
    let mut complete = 0;
    let mut failures = 0;
    for (ordinal, (seq, marker, payload)) in [
        (65_533_u16, false, vec![0x67, 0]),
        (65_534, false, vec![0x67, 1]),
        (65_535, false, vec![0x7c, 0x85, 10]),
        (65_535, false, vec![0x7c, 0x85, 10]),
        (0, true, vec![0x7c, 0x45, 20]),
        (1, false, vec![0x7c, 0x85, 30]),
        (3, true, vec![0x7c, 0x45, 40]),
        (4, true, vec![0x61, 50]),
        (5, false, vec![0x7c, 0x85, 60]),
    ].into_iter().enumerate() {
        let mut bytes = vec![0x80, 96 | if marker { 128 } else { 0 }];
        bytes.extend_from_slice(&seq.to_be_bytes());
        bytes.extend_from_slice(&90_000_u32.to_be_bytes());
        bytes.extend_from_slice(&key.ssrc.to_be_bytes());
        bytes.extend_from_slice(&payload);
        let packet = RtpPacket::parse(&bytes, PacketLimits::default())?;
        let observed = sequence.observe(key, packet)?;
        let digest = ContentDigest::try_sha256(&bytes)?.to_text();
        println!("{{\"kind\":\"packet\",\"fixture\":\"rtp-h264-loss-wrap-v1\",\"ingress\":1,\"generation\":1,\"ssrc\":7,\"ordinal\":{ordinal},\"sequence\":{seq},\"digest\":\"{digest}\",\"class\":\"{:?}\",\"missing\":{}}}", observed.class, observed.stats.missing);
        if !observed.is_unique() {
            continue;
        }
        let extended = observed.extended_sequence.ok_or("unique packet lacks extended sequence")?;
        match media.push(key, extended, packet, ordinal as u64 * 1_000_000) {
            Ok(output) => {
                for nal in output.nals {
                    complete += 1;
                    let digest = ContentDigest::try_sha256(nal.bytes())?.to_text();
                    println!("{{\"kind\":\"nal\",\"ingress\":1,\"generation\":1,\"sequence\":{extended},\"digest\":\"{digest}\",\"bytes\":{},\"source_spans\":{},\"nal_type\":{},\"marker\":{}}}", nal.bytes().len(), nal.sources().len(), nal.nal_type(), nal.marker());
                }
            }
            Err(failure) => {
                failures += 1;
                assert_eq!(failure.reason, H264Error::MissingStart);
                let discard = failure.discarded.ok_or("gap must retire the partial NAL")?;
                assert_eq!(discard.reason, H264Error::Gap);
                println!("{{\"kind\":\"discard\",\"ingress\":1,\"generation\":1,\"reason\":\"Gap\",\"first_sequence\":{},\"last_sequence\":{},\"bytes\":{}}}", discard.first_sequence, discard.last_sequence, discard.byte_len);
            }
        }
    }
    let discard = media.cancel().ok_or("final fragment must be cancelled")?;
    assert_eq!(discard.reason, H264Error::Cancelled);
    assert_eq!(media.pending_bytes(), 0);
    assert_eq!(complete, 3);
    assert_eq!(failures, 1);
    assert_eq!(sequence.stats().missing, 1);
    println!("{{\"kind\":\"terminal\",\"ingress\":1,\"generation\":1,\"complete_nals\":{complete},\"safe_failures\":{failures},\"missing\":1,\"cancelled_bytes\":{},\"pending_bytes\":0,\"qualification\":\"reference_rehearsal_only\"}}", discard.byte_len);
    Ok(())
}

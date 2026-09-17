#![forbid(unsafe_code)]
#![allow(dead_code)]
use fss_core::{BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec};
use fss_packet::{H264Limits, H264Mode, PacketLimits, RtcpMode, StreamKey};
use fss_reference::{ReplayCx, ADP_REPLAY_ROW_ID};
use fss_reference::ingest::ADP_FILE_ROW_ID;
use fss_reference::ingest::rtpdump::{RtpDumpLimits, replay::RtpReplayConfig};

pub type Error = Box<dyn std::error::Error>;
pub type TestResult = Result<(), Error>;
pub fn cx() -> Result<ReplayCx, Error> {
    let auth = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rtpdump-test".into(), operation_id: OperationId::parse("operation:rtpdump-test")?,
        principal: "operator:rtpdump-test".into(), capabilities: vec![ADP_REPLAY_ROW_ID.into(), ADP_FILE_ROW_ID.into()],
        deadline: None, priority: 10, budgets: BudgetVector::default(), privacy_scope: "privacy:internal".into(),
        retention_scope: "retention:ephemeral".into(), anchor_universe: ContentDigest::sha256(b"rtpdump-tests"), generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(&auth, std::path::Path::new(env!("CARGO_TARGET_TMPDIR")))?)
}
pub fn config() -> RtpReplayConfig {
    RtpReplayConfig { key: StreamKey { ingress: 7, generation: 1, ssrc: 7 }, payload_type: 96,
        mode: H264Mode::NonInterleaved, dump: RtpDumpLimits { max_records: 64, ..RtpDumpLimits::default() },
        packet: PacketLimits::default(), codec: H264Limits::default(), rtcp: RtcpMode::Compound }
}
pub fn header() -> Vec<u8> {
    let mut b = b"#!rtpplay1.0 0.0.0.0/0\n".to_vec(); b.extend_from_slice(&[0; 16]); b
}
pub fn rtp(seq: u16, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0x80, 96 | if marker {128} else {0}];
    b.extend_from_slice(&seq.to_be_bytes()); b.extend_from_slice(&90000_u32.to_be_bytes());
    b.extend_from_slice(&7_u32.to_be_bytes()); b.extend_from_slice(payload); b
}
pub fn record(b: &mut Vec<u8>, packet: &[u8], plen: u16, offset: u32) {
    b.extend_from_slice(&((packet.len() + 8) as u16).to_be_bytes());
    b.extend_from_slice(&plen.to_be_bytes()); b.extend_from_slice(&offset.to_be_bytes()); b.extend_from_slice(packet);
}
pub fn dump(packets: &[(u16, bool, &[u8], u32)]) -> Vec<u8> {
    let mut b = header();
    for (seq, marker, payload, offset) in packets {
        let wire = rtp(*seq, *marker, payload); record(&mut b, &wire, wire.len() as u16, *offset);
    }
    b
}
/// Retained first-party decodable Baseline fixture. This scanner is fixture setup,
/// not a replacement packet parser or a mocked reconstruction owner.
pub fn nals() -> Vec<&'static [u8]> {
    let b: &'static [u8] = include_bytes!("../../../fss-packet/tests/fixtures/avc/baseline.264");
    let mut starts = Vec::new(); let mut at = 0;
    while at + 3 <= b.len() {
        let prefix = if b.get(at..at+4) == Some(&[0,0,0,1]) {4}
            else if b[at..at+3] == [0,0,1] {3} else {0};
        if prefix > 0 { starts.push((at, at+prefix)); at += prefix; } else {at += 1;}
    }
    starts.iter().enumerate().map(|(i, (_, start))| {
        let mut end = starts.get(i+1).map_or(b.len(), |s| s.0);
        while end > *start && b[end-1] == 0 {end -= 1;}
        &b[*start..end]
    }).collect()
}
pub fn real_dump(fragmented: bool) -> Vec<u8> {
    let mut b = header(); let mut seq = 65534_u16;
    let priming = rtp(seq, false, &[0x09, 0xf0]); record(&mut b, &priming, priming.len() as u16, 0);
    seq = seq.wrapping_add(1);
    for (i, n) in nals().iter().enumerate() {
        if fragmented && matches!(n[0] & 31, 1 | 5) {
            let mid = 1 + (n.len()-1)/2;
            for (j, bytes) in [&n[1..mid], &n[mid..]].into_iter().enumerate() {
                let mut payload = vec![(n[0] & 0x60) | 28, (n[0] & 31) | if j == 0 {128} else {64}];
                payload.extend_from_slice(bytes);
                let wire = rtp(seq, j == 1, &payload); record(&mut b, &wire, wire.len() as u16, i as u32);
                seq = seq.wrapping_add(1);
            }
        } else {
            let wire = rtp(seq, matches!(n[0] & 31, 1 | 5), n); record(&mut b, &wire, wire.len() as u16, i as u32);
            seq = seq.wrapping_add(1);
        }
    }
    b
}

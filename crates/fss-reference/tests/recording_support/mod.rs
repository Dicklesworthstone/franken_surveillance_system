#![forbid(unsafe_code)]
#![allow(dead_code)]

use fss_container::TimedAvcPicture;
use fss_core::{ContentDigest, SensorId, StreamId};
use fss_packet::{H264Mode, StreamKey};
use fss_packet::avc::{AvcAssemblyStep, AvcPictureGroup, AvcReceiveLimits, AvcReceivePoll, AvcReceiver, parse_pps, parse_sps};
use fss_reference::rtsp::recording::{PreparedRecording, RecordingPacket, RecordingScope, prepare_recording};

pub type Error = Box<dyn std::error::Error>;
pub struct Fixture {
    pub pictures: Vec<AvcPictureGroup>,
    pub packets: Vec<(u64, u64, Vec<u8>)>,
}
impl Fixture {
    pub fn prepare(&self) -> Result<PreparedRecording, Error> {
        let timed: Vec<_> = self.pictures.iter().enumerate().map(|(i, picture)| TimedAvcPicture {
            picture, decode_time: i as u64 * 3600, duration: 3600, composition_offset: 0,
        }).collect();
        let source: Vec<_> = self.packets.iter().map(|(sequence, received_ns, bytes)| RecordingPacket {
            sequence: *sequence, received_ns: *received_ns, bytes,
        }).collect();
        Ok(prepare_recording(scope()?, 90_000, &timed, &source)?)
    }
}
pub fn scope() -> Result<RecordingScope, Error> {
    Ok(RecordingScope { sensor: SensorId::parse("sensor-fixture")?, stream: StreamId::parse("stream-fixture")?,
        generation: 1, anchor: ContentDigest::sha256(b"owner-authority-anchor"),
        receive_clock: ContentDigest::sha256(b"host-clock-epoch") })
}
pub fn fixture(ingress: u128, fragmented: bool) -> Result<Fixture, Error> {
    let nals = split(include_bytes!("../../../fss-packet/tests/fixtures/avc/baseline.264"));
    let limits = AvcReceiveLimits::default();
    let sps = parse_sps(nals.first().ok_or("missing SPS")?, limits.syntax)?;
    let pps = parse_pps(nals.get(1).ok_or("missing PPS")?, &sps, limits.syntax)?;
    let key = StreamKey { ingress, generation: 1, ssrc: 7 };
    let mut receiver = AvcReceiver::new(key, 96, H264Mode::NonInterleaved, limits, (sps, pps))?;
    receiver.ingest(key, &packet(0, false, nals[0]), 0)?; // sequence probation, not recording source
    let mut result = Fixture { pictures: Vec::new(), packets: Vec::new() };
    let mut seq = 1_u16;
    for nal in nals {
        let vcl = matches!(nal[0] & 31, 1 | 5);
        let payloads = if vcl && fragmented {
            let third = (nal.len() - 1) / 3;
            let parts = [&nal[1..1 + third], &nal[1 + third..1 + 2 * third], &nal[1 + 2 * third..]];
            parts.iter().enumerate().map(|(i, body)| {
                let mut p = vec![(nal[0] & 0x60) | 28, (nal[0] & 31) | if i == 0 { 128 } else if i == 2 { 64 } else { 0 }];
                p.extend_from_slice(body); p
            }).collect::<Vec<_>>()
        } else { vec![nal.to_vec()] };
        let last = payloads.len() - 1;
        for (i, payload) in payloads.into_iter().enumerate() {
            let wire = packet(seq, vcl && i == last, &payload);
            receiver.ingest(key, &wire, u64::from(seq))?;
            result.packets.push((u64::from(seq), u64::from(seq), wire));
            drain(&mut receiver, u64::from(seq), &mut result.pictures)?;
            seq += 1;
        }
        if vcl { break; }
    }
    if result.pictures.len() != 1 { return Err("fixture did not produce one marker-bounded IDR group".into()); }
    Ok(result)
}
fn drain(receiver: &mut AvcReceiver, now: u64, out: &mut Vec<AvcPictureGroup>) -> Result<(), Error> {
    for _ in 0..1024 {
        match receiver.poll(now)? {
            AvcReceivePoll::Source { gap_before: false, picture: None, fragment: None, .. } => {}
            AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(output)) => {
                if output.retired.is_some() { return Err("clean fixture retired".into()); }
                if let Some(p) = output.picture { out.push(p); }
            }
            AvcReceivePoll::Picture(p) => out.push(p),
            AvcReceivePoll::Pending { .. } => return Ok(()),
            other => return Err(format!("unexpected fixture outcome: {other:?}").into()),
        }
    }
    Err("fixture poll bound".into())
}
pub fn packet(sequence: u16, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, 96 | if marker { 128 } else { 0 }];
    bytes.extend_from_slice(&sequence.to_be_bytes()); bytes.extend_from_slice(&90_000_u32.to_be_bytes());
    bytes.extend_from_slice(&7_u32.to_be_bytes()); bytes.extend_from_slice(payload); bytes
}
fn split(bytes: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new(); let mut start = None; let mut at = 0;
    while at + 3 <= bytes.len() {
        let prefix = if bytes.get(at..at + 4) == Some(&[0, 0, 0, 1]) { 4 }
            else if bytes[at..at + 3] == [0, 0, 1] { 3 } else { 0 };
        if prefix != 0 {
            if let Some(begin) = start {
                let mut end = at;
                while end > begin && bytes[end - 1] == 0 { end -= 1; }
                if begin < end { out.push(&bytes[begin..end]); }
            }
            start = Some(at + prefix); at += prefix;
        } else { at += 1; }
    }
    if let Some(begin) = start { if begin < bytes.len() { out.push(&bytes[begin..]); } }
    out
}

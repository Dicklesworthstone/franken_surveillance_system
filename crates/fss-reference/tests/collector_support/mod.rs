#![forbid(unsafe_code)]
#![allow(dead_code)]

use fss_core::{ContentDigest, SensorId, StreamId};
use fss_packet::{H264Mode, StreamKey};
use fss_packet::avc::{AvcAssemblyStep, AvcPictureGroup, AvcReceiveLimits, AvcReceivePoll,
    AvcReceiver, parse_pps, parse_sps};
use fss_reference::rtsp::recording::{RecordingPacket, RecordingScope};
use fss_reference::rtsp::recording_collector::{CollectedPicture, CollectorAdmission,
    CollectorLimits, RecordingCollector, RecordingTiming};

pub type Error = Box<dyn std::error::Error>;
pub type TestResult = Result<(), Error>;

pub fn key() -> StreamKey { StreamKey { ingress: 31, generation: 1, ssrc: 7 } }
pub fn scope() -> Result<RecordingScope, Error> {
    Ok(RecordingScope { sensor: SensorId::parse("collector-fixture")?, stream: StreamId::parse("video")?,
        generation: 1, anchor: ContentDigest::sha256(b"owner-anchor"),
        receive_clock: ContentDigest::sha256(b"receiver-clock-epoch") })
}
pub fn collector(limits: CollectorLimits) -> Result<RecordingCollector, Error> {
    Ok(RecordingCollector::new(scope()?, key(), 96, 90_000, limits)?)
}
pub fn timing(decode_time: u64) -> RecordingTiming {
    RecordingTiming { decode_time, duration: 3600, composition_offset: 0 }
}
pub struct Sample {
    pub picture: AvcPictureGroup,
    pub packets: Vec<(u64, Vec<u8>)>,
}
impl Sample {
    pub fn source(&self, c: &mut RecordingCollector, now: u64) -> TestResult {
        for (seq, bytes) in &self.packets {
            c.push_source(key(), RecordingPacket { sequence: *seq, received_ns: *seq, bytes }, now)?;
        }
        Ok(())
    }
    pub fn timed(self, decode_time: u64) -> CollectedPicture {
        CollectedPicture { picture: self.picture, timing: timing(decode_time) }
    }
}
pub fn accepted(out: CollectorAdmission) -> Result<bool, Error> {
    match out {
        CollectorAdmission::Accepted { window_ready, unselected } if unselected.is_empty() => Ok(window_ready),
        other => Err(format!("unexpected admission: {other:?}").into()),
    }
}

/// Use real synthetic Baseline VCL bytes, not hand-built entropy payloads.
pub fn sample(first_seq: u64, timestamp: u32, idr: bool, fragmented: bool) -> Result<Sample, Error> {
    let raw = nals();
    let nal = raw.iter().find(|n| n[0] & 31 == if idr { 5 } else { 1 }).ok_or("missing VCL")?;
    let payloads = if fragmented {
        let half = 1 + (nal.len() - 1) / 2;
        [&nal[1..half], &nal[half..]].iter().enumerate().map(|(i, body)| {
            let mut p = vec![(nal[0] & 0x60) | 28, (nal[0] & 31) | if i == 0 { 128 } else { 64 }];
            p.extend_from_slice(body); p
        }).collect::<Vec<_>>()
    } else { vec![nal.to_vec()] };
    let mut receiver = receiver()?;
    receiver.ingest(key(), &packet(first_seq - 1, timestamp, false, raw[0]), 0)?;
    let mut packets = Vec::new(); let mut pictures = Vec::new();
    let count = payloads.len();
    for (i, payload) in payloads.into_iter().enumerate() {
        let seq = first_seq + i as u64;
        let wire = packet(seq, timestamp, i + 1 == count, &payload);
        receiver.ingest(key(), &wire, i as u64 + 1)?;
        packets.push((seq, wire));
        pictures.extend(drain(&mut receiver, i as u64 + 1)?);
    }
    if pictures.len() != 1 { return Err("sample did not produce exactly one picture".into()); }
    Ok(Sample { picture: pictures.remove(0), packets })
}
pub fn receiver() -> Result<AvcReceiver, Error> {
    let raw = nals(); let limits = AvcReceiveLimits::default();
    let sps = parse_sps(raw[0], limits.syntax)?;
    let pps = parse_pps(raw[1], &sps, limits.syntax)?;
    Ok(AvcReceiver::new(key(), 96, H264Mode::NonInterleaved, limits, (sps, pps))?)
}
pub fn drain(receiver: &mut AvcReceiver, now: u64) -> Result<Vec<AvcPictureGroup>, Error> {
    let mut pictures = Vec::new();
    for _ in 0..1024 {
        match receiver.poll(now)? {
            AvcReceivePoll::Source { gap_before: false, picture: None, fragment: None, .. } => {}
            AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(out)) if out.retired.is_none() => {
                if let Some(p) = out.picture { pictures.push(p); }
            }
            AvcReceivePoll::Picture(p) => pictures.push(p),
            AvcReceivePoll::Pending { .. } => return Ok(pictures),
            event => return Err(format!("unexpected clean fixture event {event:?}").into()),
        }
    }
    Err("fixture poll bound".into())
}
pub fn packet(sequence: u64, timestamp: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, 96 | if marker { 128 } else { 0 }];
    bytes.extend_from_slice(&(sequence as u16).to_be_bytes());
    bytes.extend_from_slice(&timestamp.to_be_bytes()); bytes.extend_from_slice(&key().ssrc.to_be_bytes());
    bytes.extend_from_slice(payload); bytes
}
pub fn nals() -> Vec<&'static [u8]> {
    let bytes: &'static [u8] = include_bytes!("../../../fss-packet/tests/fixtures/avc/baseline.264");
    let mut out = Vec::new(); let mut start = None; let mut at = 0;
    while at + 3 <= bytes.len() {
        let prefix = if bytes.get(at..at + 4) == Some(&[0, 0, 0, 1]) { 4 }
            else if bytes[at..at + 3] == [0, 0, 1] { 3 } else { 0 };
        if prefix != 0 {
            if let Some(begin) = start {
                let mut end = at; while end > begin && bytes[end - 1] == 0 { end -= 1; }
                if begin < end { out.push(&bytes[begin..end]); }
            }
            start = Some(at + prefix); at += prefix;
        } else { at += 1; }
    }
    if let Some(begin) = start { if begin < bytes.len() { out.push(&bytes[begin..]); } }
    out
}

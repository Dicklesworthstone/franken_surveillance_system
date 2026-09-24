#![forbid(unsafe_code)]
#![allow(dead_code)]

use fss_core::{CanonicalEncoder, ContentDigest, SensorId, StreamId};
use fss_packet::hevc::{HevcConfiguration, HevcConfigurationLimits};
use fss_reference::rtsp::recording::hevc::{
    HevcRecordingTiming, PreparedHevcRecording, prepare_hevc_recording,
};
use fss_reference::rtsp::recording::{RecordingPacket, RecordingScope};

pub type Error = Box<dyn std::error::Error>;
pub const PT: u8 = 98;
pub const SSRC: u32 = 7;
pub const FIXTURE: &str =
    include_str!("../../../../tests/fixtures/media/hevc/remux_main8.nals.hex");

pub fn nals() -> Result<Vec<Vec<u8>>, Error> {
    FIXTURE
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            if !line.is_ascii() || line.len() % 2 != 0 {
                return Err("invalid hex fixture".into());
            }
            (0..line.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&line[at..at + 2], 16).map_err(|e| e.into()))
                .collect()
        })
        .collect()
}
pub fn configuration() -> Result<HevcConfiguration, Error> {
    let n = nals()?;
    Ok(HevcConfiguration::parse(
        n.first().ok_or("VPS")?,
        n.get(1).ok_or("SPS")?,
        n.get(2).ok_or("PPS")?,
        HevcConfigurationLimits::default(),
    )?)
}
pub fn scope() -> Result<RecordingScope, Error> {
    Ok(RecordingScope {
        sensor: SensorId::parse("sensor-hevc-fixture")?,
        stream: StreamId::parse("stream-hevc-fixture")?,
        generation: 1,
        anchor: ContentDigest::sha256(b"explicit-owner-anchor"),
        receive_clock: ContentDigest::sha256(b"explicit-receive-clock"),
    })
}
#[derive(Clone)]
pub struct Packet {
    pub sequence: u64,
    pub received_ns: u64,
    pub bytes: Vec<u8>,
}
pub fn packet(sequence: u64, timestamp: u32, marker: bool, payload: &[u8]) -> Packet {
    let mut bytes = vec![0x80, PT | if marker { 128 } else { 0 }];
    bytes.extend_from_slice(&(sequence as u16).to_be_bytes());
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&SSRC.to_be_bytes());
    bytes.extend_from_slice(payload);
    Packet {
        sequence,
        received_ns: 100 + sequence,
        bytes,
    }
}
pub fn packets() -> Result<Vec<Packet>, Error> {
    let times = [0, 0, 0, 0, 18_000, 36_000, 36_000, 36_000, 36_000, 54_000];
    let mut packets: Vec<_> = times
        .into_iter()
        .zip(nals()?)
        .enumerate()
        .map(|(i, (time, nal))| packet(65_533 + i as u64, time, true, &nal))
        .collect();
    // Explicit fixture EOS, never an implementation-generated EOF boundary.
    packets.push(packet(65_543, 54_000, true, &[0x48, 1, 0x80]));
    Ok(packets)
}
pub fn borrowed(packets: &[Packet]) -> Vec<RecordingPacket<'_>> {
    packets
        .iter()
        .map(|p| RecordingPacket {
            sequence: p.sequence,
            received_ns: p.received_ns,
            bytes: &p.bytes,
        })
        .collect()
}
pub fn timings(count: usize) -> Vec<HevcRecordingTiming> {
    (0..count)
        .map(|i| HevcRecordingTiming {
            decode_time: i as u64 * 18_000,
            duration: 18_000,
            composition_offset: 0,
        })
        .collect()
}
pub fn prepare(
    packets: &[Packet],
    timings: &[HevcRecordingTiming],
) -> Result<PreparedHevcRecording, Error> {
    Ok(prepare_hevc_recording(
        scope()?,
        &configuration()?,
        90_000,
        timings,
        &borrowed(packets),
    )?)
}
pub fn fixture() -> Result<PreparedHevcRecording, Error> {
    prepare(&packets()?, &timings(4))
}
pub fn aggregate(nals: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = vec![0x60, 1];
    for n in nals {
        payload.extend_from_slice(&(n.len() as u16).to_be_bytes());
        payload.extend_from_slice(n);
    }
    payload
}
pub fn pack(packets: &[Packet]) -> Result<Vec<u8>, Error> {
    let mut e = CanonicalEncoder::new();
    e.text("fss.recording_window.source.v1");
    e.u64(packets.len() as u64);
    for p in packets {
        e.u64(p.sequence);
        e.u64(p.received_ns);
        e.bytes(&p.bytes);
    }
    Ok(e.finish_checked()?)
}

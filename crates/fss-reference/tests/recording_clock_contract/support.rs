#![forbid(unsafe_code)]
//! Real AVC source custody and an explicitly unauthenticated local clock fixture.

pub use crate::collector_support::{Error, TestResult};
use crate::collector_support::{accepted, collector, key, sample};
use fss_core::ContentDigest;
use fss_packet::ntp::SntpRequest;
use fss_publication::SlotName;
use fss_reference::rtsp::recording::{PreparedRecording, RecordingPacket};
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_clock::{
    ClockWindow, ReceiveClockBracket, RecordingClockCodec, RecordingClockIndex,
};
use fss_reference::rtsp::recording_collector::CollectorLimits;
use fss_reference::site::clock::HostClockSample;
use fss_reference::site::clock_proof::{LOCAL_NTP_CLOCK_POLICY, LocalNtpExchange};

pub const EPOCH: u64 = 1_800_000_000_000_000_000;

pub fn host(monotonic_ns: u64) -> HostClockSample {
    HostClockSample {
        monotonic_before_ns: monotonic_ns,
        wall_clock_unix_ns: EPOCH + monotonic_ns,
        monotonic_after_ns: monotonic_ns,
    }
}

pub fn bracket(admission_ns: u64) -> ReceiveClockBracket {
    ReceiveClockBracket {
        admission_ns,
        completed: HostClockSample {
            monotonic_before_ns: admission_ns + 1_000,
            wall_clock_unix_ns: EPOCH + admission_ns + 1_500,
            monotonic_after_ns: admission_ns + 2_000,
        },
    }
}

pub fn catalog_scope() -> Result<CatalogScope, Error> {
    Ok(CatalogScope {
        recording: crate::collector_support::scope()?,
        decode_clock: ContentDigest::try_sha256(b"retained clock explicit DTS epoch")?,
        time_scale: 90_000,
    })
}

pub fn approval() -> ContentDigest {
    ContentDigest::sha256(b"explicit local read clock fixture approval")
}

fn put_timestamp(packet: &mut [u8; 48], start: usize, unix_ns: u64) {
    let seconds = (unix_ns / 1_000_000_000 + 2_208_988_800) as u32;
    let fraction = ((u128::from(unix_ns % 1_000_000_000) << 32) / 1_000_000_000) as u32;
    packet[start..start + 4].copy_from_slice(&seconds.to_be_bytes());
    packet[start + 4..start + 8].copy_from_slice(&fraction.to_be_bytes());
}

pub fn exchange() -> Result<LocalNtpExchange, Error> {
    let request = SntpRequest::new(EPOCH)?;
    let mut reply = [0_u8; 48];
    reply[0] = 0x24;
    reply[1] = 2;
    reply[2] = 6;
    reply[3] = (-30_i8) as u8;
    reply[12..16].copy_from_slice(b"TEST");
    put_timestamp(&mut reply, 16, EPOCH - 1_000_000_000);
    reply[24..32].copy_from_slice(&request.wire_bytes()[40..48]);
    put_timestamp(&mut reply, 32, EPOCH + 1_009_000_000);
    put_timestamp(&mut reply, 40, EPOCH + 1_010_000_000);
    Ok(LocalNtpExchange {
        peer: "127.0.0.1:123".parse()?,
        request: *request.wire_bytes(),
        reply,
        sent_before: host(0),
        sent_after: host(1_000),
        received_before: host(20_000_000),
        received_after: host(20_001_000),
        policy: LOCAL_NTP_CLOCK_POLICY,
    })
}

pub fn window(seq: u64, dts: u64, admissions: &[u64]) -> Result<PreparedRecording, Error> {
    if !(1..=2).contains(&admissions.len()) {
        return Err("fixture requires one packet or two source fragments".into());
    }
    let mut receiver = collector(CollectorLimits::default())?;
    let picture = sample(seq, 90_000 + seq as u32 * 3600, true, admissions.len() == 2)?;
    if picture.packets.len() != admissions.len() {
        return Err("fixture packet count".into());
    }
    for ((sequence, bytes), received_ns) in picture.packets.iter().zip(admissions) {
        receiver.push_source(
            key(),
            RecordingPacket {
                sequence: *sequence,
                received_ns: *received_ns,
                bytes,
            },
            100_000_000,
        )?;
    }
    accepted(receiver.push_picture(picture.timed(dts), 100_000_000))?;
    receiver.seal(100_000_001)?;
    receiver
        .take_ready()
        .ok_or_else(|| "missing native window".into())
}

pub fn descriptor(name: &str, recording: &PreparedRecording) -> Result<ClockWindow, Error> {
    Ok(ClockWindow::from_avc(SlotName::parse(name)?, recording)?)
}

pub fn prepare(
    windows: &[ClockWindow],
    brackets: &[ReceiveClockBracket],
) -> Result<RecordingClockIndex, Error> {
    Ok(RecordingClockIndex::prepare(
        catalog_scope()?,
        RecordingClockCodec::Avc,
        approval(),
        exchange()?,
        host(100_000_000),
        brackets,
        windows,
    )?)
}

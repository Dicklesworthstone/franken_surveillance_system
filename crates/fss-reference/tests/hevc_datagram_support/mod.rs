#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Native HEVC originals persisted through real framing and root-last custody.
#[path = "../hevc_recording_support/mod.rs"]
pub mod media;
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_object::SpoolLimits;
use fss_packet::{H265Limits, ReorderLimits, StreamKey};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel};
use fss_reference::rtsp::datagram_archive::{
    DatagramArchive, DatagramArchiveLimits, DatagramPin, DatagramScope,
};
use fss_reference::rtsp::datagram_reconstruction::hevc::{HevcReplayBounds, HevcReplaySpec};
use fss_reference::rtsp::framed::RtspWireIntake;
use fss_reference::rtsp::tcp::{TcpBinding, TcpSecurityPolicy};
use std::path::{Path, PathBuf};

pub type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub const KEY: StreamKey = StreamKey {
    ingress: 73,
    generation: 1,
    ssrc: media::SSRC,
};
pub type Observation = (u8, u64, Vec<u8>);
pub fn work() -> WorkBudget<'static> {
    WorkBudget::new(1_000_000_000_000)
}
pub fn storage() -> LocalPublicationLimits {
    LocalPublicationLimits::new(
        128,
        512,
        128,
        1024,
        SpoolLimits::new(1024, 64 * 1024 * 1024, 2 * 1024 * 1024, 1024),
    )
}
pub fn scope() -> Test<DatagramScope> {
    Ok(DatagramScope {
        binding: TcpBinding::new(
            KEY,
            "127.0.0.1:554".parse()?,
            "camera.local",
            TcpSecurityPolicy::OwnerApprovedPlaintext,
        )?,
        channels: (0, 1),
        receive_clock: media::scope()?.receive_clock,
        retention_evidence: ContentDigest::sha256(b"explicit original RTP and RTCP retention"),
    })
}
pub fn limits() -> DatagramArchiveLimits {
    DatagramArchiveLimits {
        max_datagrams: 128,
        max_payload_bytes: 1024 * 1024,
        max_scan_roots: 1024,
        max_spool_object_bytes: 2 * 1024 * 1024,
    }
}
pub fn spec() -> HevcReplaySpec {
    HevcReplaySpec {
        payload_type: media::PT,
        sprop_max_don_diff: 0,
        reorder: ReorderLimits::default(),
        reconstruction: H265Limits::default(),
        reduced_rtcp: false,
        configuration_evidence: ContentDigest::sha256(
            b"owner selected HEVC SRST/no-DON RTP mapping",
        ),
    }
}
pub fn bounds() -> HevcReplayBounds {
    HevcReplayBounds {
        max_source_bytes: 1024 * 1024,
        max_steps: 4096,
        deadline_ns: u64::MAX,
    }
}
pub fn raw(seq: u64, timestamp: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    media::packet(seq, timestamp, marker, payload).bytes
}
pub fn observations(fragmented: bool) -> Test<Vec<Observation>> {
    let n = media::nals()?;
    let mut out = vec![(0, 10, raw(1, 9000, false, &n[0]))]; // probation
    let idr = n
        .iter()
        .find(|n| matches!((n[0] >> 1) & 63, 19 | 20))
        .ok_or("IDR")?;
    if fragmented {
        let mid = 2 + (idr.len() - 2) / 2;
        for (i, data) in [&idr[2..mid], &idr[mid..]].into_iter().enumerate() {
            let mut payload = vec![
                (idr[0] & 0x81) | (49 << 1),
                idr[1],
                ((idr[0] >> 1) & 63) | if i == 0 { 128 } else { 64 },
            ];
            payload.extend_from_slice(data);
            out.push((0, 11 + i as u64, raw(2 + i as u64, 9000, i == 1, &payload)));
        }
    } else {
        out.push((0, 11, raw(2, 9000, true, idr)));
    }
    Ok(out)
}
pub fn fresh(name: &str) -> Test<PathBuf> {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("hevc_datagram_replay")
        .join(name);
    match std::fs::remove_dir_all(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(path)
}
pub fn append(p: &mut LocalRootPublisher, a: &mut DatagramArchive, input: &[Observation]) -> Test {
    for (channel, time, bytes) in input {
        let mut wire = vec![b'$', *channel];
        wire.extend_from_slice(&u16::try_from(bytes.len())?.to_be_bytes());
        wire.extend_from_slice(bytes);
        let mut intake = RtspWireIntake::new();
        let mut frame = None;
        for part in wire.chunks(7) {
            intake.ingest(part, *time)?;
            if let Some(f) = intake.poll(*time)? {
                assert!(frame.is_none());
                frame = Some(f);
            }
        }
        let frame = frame.ok_or("missing frame")?;
        let prepared = a.prepare_frame(&frame, &mut work())?;
        let receipt = a.publish(&prepared, p, &NeverCancel, &mut work())?;
        assert_eq!(receipt.record.payload_bytes, bytes.len());
    }
    Ok(())
}
pub fn save(path: &Path, input: &[Observation]) -> Test<DatagramPin> {
    let mut p = LocalRootPublisher::open(path, storage())?;
    let mut a = DatagramArchive::new(scope()?, limits())?;
    append(&mut p, &mut a, input)?;
    Ok(a.pin())
}
pub fn reopen(path: &Path, pin: DatagramPin) -> Test<(LocalRootPublisher, DatagramArchive)> {
    let p = LocalRootPublisher::open(path, storage())?;
    let a = DatagramArchive::recover(&p, scope()?, limits(), Some(pin), &NeverCancel, &mut work())?;
    Ok((p, a))
}

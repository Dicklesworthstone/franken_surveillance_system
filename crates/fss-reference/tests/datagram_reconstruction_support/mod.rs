#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Public-API fixture: opaque original datagrams from real Digest/RTSP parsing into real custody.
#[path = "../digest_media_support/mod.rs"]
pub mod source;

use std::path::{Path, PathBuf};
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_object::SpoolLimits;
use fss_packet::H264Mode;
use fss_packet::avc::AvcReceiveLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel};
use fss_reference::rtsp::avc_client::{AvcClientPoll, authenticated::DigestAvcPoll};
use fss_reference::rtsp::datagram_archive::{DatagramArchive, DatagramLimits, DatagramPin, DatagramScope};
use fss_reference::rtsp::datagram_reconstruction::{AvcReplayBounds, AvcReplaySpec};
use fss_reference::rtsp::tcp::{TcpBinding, TcpSecurityPolicy};

pub type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub fn work() -> WorkBudget<'static> { WorkBudget::new(1_000_000_000_000) }
pub fn storage() -> LocalPublicationLimits {
    LocalPublicationLimits::new(128, 16, 128, 1024,
        SpoolLimits::new(1024, 16 * 1024 * 1024, 65536, 1024))
}
pub fn scope() -> Test<DatagramScope> {
    Ok(DatagramScope { binding: TcpBinding::new(source::KEY, "127.0.0.1:554".parse()?,
        "camera.local", TcpSecurityPolicy::OwnerApprovedPlaintext)?, channels: (0, 1),
        receive_clock: ContentDigest::sha256(b"reconstruction receive epoch"),
        retention_evidence: ContentDigest::sha256(b"owner authorized source retention") })
}
pub fn limits() -> DatagramLimits {
    DatagramLimits { max_datagrams: 128, max_payload_bytes: 1024 * 1024,
        max_scan_roots: 1024, max_spool_object_bytes: 65536 }
}
pub fn spec() -> Test<AvcReplaySpec<'static>> {
    let nals = source::nals();
    Ok(AvcReplaySpec { payload_type: 96, mode: H264Mode::NonInterleaved,
        sps: nals.iter().copied().find(|n| n[0] & 31 == 7).ok_or("SPS missing")?,
        pps: nals.iter().copied().find(|n| n[0] & 31 == 8).ok_or("PPS missing")?,
        limits: AvcReceiveLimits::default(), reduced_rtcp: false,
        configuration_evidence: ContentDigest::sha256(b"owner pinned fixture SDP and replay policy") })
}
pub fn bounds() -> AvcReplayBounds {
    AvcReplayBounds { max_source_bytes: 1024 * 1024, max_steps: 4096, deadline_ns: u64::MAX }
}
pub fn raw(seq: u16, timestamp: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = source::packet(seq, timestamp, payload);
    if marker { bytes[1] |= 128; }
    bytes
}
/// RTP probation followed by one marker-bounded real encoded IDR, optionally FU-A fragmented.
pub fn observations(fragmented: bool) -> Test<Vec<(u8, u64, Vec<u8>)>> {
    let s = spec()?;
    let nals = source::nals();
    let idr = nals.iter().copied().find(|n| n[0] & 31 == 5).ok_or("IDR missing")?;
    let mut out = vec![(0, 10, raw(1, 9000, false, s.sps))];
    if fragmented {
        let mid = 1 + (idr.len() - 1) / 2;
        for (i, data) in [&idr[1..mid], &idr[mid..]].into_iter().enumerate() {
            let mut payload = vec![(idr[0] & 0x60) | 28, (idr[0] & 31) | if i == 0 { 128 } else { 64 }];
            payload.extend_from_slice(data);
            out.push((0, 11 + i as u64, raw(2 + i as u16, 9000, i == 1, &payload)));
        }
    } else { out.push((0, 11, raw(2, 9000, true, idr))); }
    Ok(out)
}
pub fn fresh(name: &str) -> Test<PathBuf> {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("datagram_reconstruction").join(name);
    match std::fs::remove_dir_all(&path) {
        Ok(()) => {}, Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}, Err(e) => return Err(e.into()),
    }
    Ok(path)
}
/// Discard all original in-memory protocol/media/custody state after publishing; callers reopen.
pub fn save(path: &Path, observations: &[(u8, u64, Vec<u8>)]) -> Test<DatagramPin> {
    let mut publisher = LocalRootPublisher::open(path, storage())?;
    let mut archive = DatagramArchive::new(scope()?, limits())?;
    let mut parser = source::playing()?;
    for (channel, now, payload) in observations {
        let mut events = Vec::new();
        source::send(&mut parser, &source::interleaved(*channel, payload), 4096, *now, &mut events)?;
        let mut seen = 0;
        for event in events {
            let original = match event {
                DigestAvcPoll::Client { event, .. } => match *event {
                    AvcClientPoll::Rtp { source, .. } | AvcClientPoll::Rtcp { source, .. } => Some(source),
                    AvcClientPoll::Fault { source, .. } => source,
                    _ => None,
                },
                _ => None,
            };
            if let Some(original) = original {
                assert_eq!(original.payload(), payload);
                let prepared = archive.prepare(&original, &mut work())?;
                let _ = archive.publish(&prepared, &mut publisher, &NeverCancel, &mut work())?;
                seen += 1;
            }
        }
        assert_eq!(seen, 1, "one opaque original per fixture observation");
    }
    Ok(archive.pin())
}
pub fn reopen(path: &Path, pin: DatagramPin) -> Test<(LocalRootPublisher, DatagramArchive)> {
    let publisher = LocalRootPublisher::open(path, storage())?;
    let archive = DatagramArchive::recover(&publisher, scope()?, Some(pin), limits(), &NeverCancel, &mut work())?;
    assert_eq!(archive.pin(), pin);
    Ok((publisher, archive))
}

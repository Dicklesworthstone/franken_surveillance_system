#![forbid(unsafe_code)]
//! Real native fixture construction; timestamp bytes are inserted before source replay.

use std::path::PathBuf;

use fss_core::ContentDigest;
use fss_packet::H264Mode;
use fss_packet::avc::{
    AvcAssemblyStep, AvcPictureGroup, AvcReceiveLimits, AvcReceivePoll, AvcReceiver,
};
use fss_publication::{LocalRootPublisher, NeverCancel};
use fss_reference::rtsp::client::replay::ReplayAcceptance;
use fss_reference::rtsp::recording::hevc::HevcRecordingTiming;
use fss_reference::rtsp::recording_archive::ArchiveNamespace;
use fss_reference::rtsp::recording_archive::hevc::HevcArchiveNamespace;
use fss_reference::rtsp::recording_replay::time::{ReplayTimeLimits, ReplayTimeQuery};
use fss_reference::rtsp::recording_replay::{
    ReplayReceipt, ReplayRequest, ReplayTermination, ReplayWindowProof, publish_replay_receipt,
};

use super::super::{
    Error, TestResult, accepted, catalog_scope, hevc_recording_support as hevc, limits, path,
    publish_window, recording_support, request,
};

pub(super) const NTP_SECONDS: u32 = 4_002_829_320;
pub(super) const UTC_NS: i128 = 1_793_840_520_000_000_000;
pub(super) const ERA_NS: i128 = 4_294_967_296_000_000_000;

pub(super) fn content(seconds: u32, fraction: u32, flags: u8, cseq: u8) -> [u8; 12] {
    let mut bytes = [0_u8; 12];
    bytes[..4].copy_from_slice(&seconds.to_be_bytes());
    bytes[4..8].copy_from_slice(&fraction.to_be_bytes());
    bytes[8] = flags;
    bytes[9] = cseq;
    bytes
}

pub(super) fn raw_extension(wire: &mut Vec<u8>, profile: u16, bytes: &[u8]) -> TestResult {
    if wire.len() < 12 || wire[0] & 0x10 != 0 || bytes.len() % 4 != 0 {
        return Err("fixture needs an unextended RTP packet and complete extension words".into());
    }
    let at = 12 + usize::from(wire[0] & 15) * 4;
    if at > wire.len() {
        return Err("fixture CSRC range".into());
    }
    let words = u16::try_from(bytes.len() / 4)?;
    let mut extension = Vec::with_capacity(4 + bytes.len());
    extension.extend_from_slice(&profile.to_be_bytes());
    extension.extend_from_slice(&words.to_be_bytes());
    extension.extend_from_slice(bytes);
    wire[0] |= 0x10;
    wire.splice(at..at, extension);
    Ok(())
}

pub(super) fn stamp(
    wire: &mut Vec<u8>,
    seconds: u32,
    fraction: u32,
    flags: u8,
    cseq: u8,
) -> TestResult {
    raw_extension(wire, 0xABAC, &content(seconds, fraction, flags, cseq))
}

pub(super) fn timestamp(wire: &[u8]) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(
        wire.get(4..8).ok_or("fixture RTP timestamp")?.try_into()?,
    ))
}

/// Reconstruct every picture and source span from the changed original datagrams.
/// Reusing the old pictures after adding an RTP extension would certify wrong byte ranges.
pub(super) fn rebuild_avc(
    mut source: recording_support::Fixture,
    mut edit: impl FnMut(usize, &mut Vec<u8>) -> TestResult,
) -> Result<recording_support::Fixture, Error> {
    let picture = source.pictures.first().ok_or("fixture picture")?;
    let key = picture.key();
    let parameters = (picture.sps().clone(), picture.pps().clone());
    let expected = source.pictures.len();
    let first = source.packets.first().ok_or("fixture packet")?;
    let mut probation = first.2.clone();
    let previous = u16::try_from(first.0.checked_sub(1).ok_or("fixture probation")?)?;
    probation[2..4].copy_from_slice(&previous.to_be_bytes());
    probation[1] &= 0x7F;
    let mut receiver = AvcReceiver::new(
        key,
        96,
        H264Mode::NonInterleaved,
        AvcReceiveLimits::default(),
        parameters,
    )?;
    receiver.ingest(key, &probation, first.1.saturating_sub(1))?;
    source.pictures.clear();
    for (index, (_, now, wire)) in source.packets.iter_mut().enumerate() {
        edit(index, wire)?;
        receiver.ingest(key, wire, *now)?;
        drain_avc(&mut receiver, *now, &mut source.pictures)?;
    }
    if source.pictures.len() != expected {
        return Err("timestamp fixture changed native picture count".into());
    }
    Ok(source)
}

fn drain_avc(
    receiver: &mut AvcReceiver,
    now: u64,
    pictures: &mut Vec<AvcPictureGroup>,
) -> TestResult {
    for _ in 0..1024 {
        match receiver.poll(now)? {
            AvcReceivePoll::Source {
                gap_before: false,
                picture: None,
                fragment: None,
                ..
            } => {}
            AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(output)) => {
                if output.retired.is_some() {
                    return Err("timestamp fixture retired native source".into());
                }
                if let Some(picture) = output.picture {
                    pictures.push(picture);
                }
            }
            AvcReceivePoll::Picture(picture) => pictures.push(picture),
            AvcReceivePoll::Pending { .. } => return Ok(()),
            other => return Err(format!("timestamp fixture native outcome: {other:?}").into()),
        }
    }
    Err("timestamp fixture native poll bound".into())
}

pub(super) struct Sealed {
    pub root: PathBuf,
    pub receipt: ReplayReceipt,
}

impl Sealed {
    pub fn open(&self) -> Result<LocalRootPublisher, Error> {
        Ok(LocalRootPublisher::open(&self.root, limits())?)
    }

    pub fn query(&self) -> ReplayTimeQuery {
        ReplayTimeQuery {
            codec: self.receipt.request().codec(),
            scope: self.receipt.scope().clone(),
            receipt_root: self.receipt.root(),
            request: self.receipt.request().digest(),
            ntp_era: 0,
            start_ns: UTC_NS,
            end_ns: UTC_NS + 10_000_000_000,
            limits: ReplayTimeLimits::default(),
        }
    }
}

pub(super) fn receipt(
    request: ReplayRequest,
    windows: Vec<ReplayWindowProof>,
    cseq: u32,
) -> Result<ReplayReceipt, Error> {
    let scope = catalog_scope(&request);
    let template = accepted(&request)?;
    let acknowledgement =
        ReplayAcceptance::new(cseq, template.requested(), template.acknowledged())?;
    Ok(ReplayReceipt::prepare(
        request,
        scope,
        ContentDigest::sha256(b"approved native cold timestamp fixture"),
        acknowledgement,
        windows,
        ReplayTermination::RequestedStop,
        true,
    )?)
}

pub(super) fn seal_avc(
    name: &str,
    source: &recording_support::Fixture,
    count: usize,
    cseq: u32,
) -> Result<Sealed, Error> {
    let root = path(name);
    let mut publisher = LocalRootPublisher::open(&root, limits())?;
    let request = request()?;
    let namespace = ArchiveNamespace::new(catalog_scope(&request))?;
    let mut windows = Vec::new();
    for ordinal in 0..count {
        let recording = source.prepare_at(ordinal as u64 * 3600)?;
        let slot = namespace.window_slot(ordinal)?;
        publish_window(&mut publisher, &slot, &recording)?;
        windows.push(ReplayWindowProof::from_avc(slot, &recording)?);
    }
    let receipt = receipt(request, windows, cseq)?;
    publish_replay_receipt(&receipt, &mut publisher, &NeverCancel)?;
    drop(publisher);
    Ok(Sealed { root, receipt })
}

pub(super) fn seal_hevc(
    name: &str,
    packets: &[hevc::Packet],
    timings: &[HevcRecordingTiming],
    cseq: u32,
) -> Result<Sealed, Error> {
    let root = path(name);
    let mut publisher = LocalRootPublisher::open(&root, limits())?;
    let template = request()?;
    let request = ReplayRequest::new_hevc(
        hevc::scope()?,
        template.route(),
        template.window(),
        template.base_decode_clock(),
    )?;
    let namespace = HevcArchiveNamespace::new(catalog_scope(&request))?;
    let recording = hevc::prepare(packets, timings)?;
    let slot = namespace.window_slot(0)?;
    publish_window(&mut publisher, &slot, recording.publication_plan())?;
    let receipt = receipt(
        request,
        vec![ReplayWindowProof::from_hevc(slot, &recording)?],
        cseq,
    )?;
    publish_replay_receipt(&receipt, &mut publisher, &NeverCancel)?;
    drop(publisher);
    Ok(Sealed { root, receipt })
}

pub(super) fn stamped_hevc() -> Result<Vec<hevc::Packet>, Error> {
    let mut packets = hevc::packets()?;
    for packet in &mut packets {
        let ordinal = timestamp(&packet.bytes)? / 18_000;
        stamp(&mut packet.bytes, NTP_SECONDS + ordinal, 0, 0, 7)?;
    }
    Ok(packets)
}

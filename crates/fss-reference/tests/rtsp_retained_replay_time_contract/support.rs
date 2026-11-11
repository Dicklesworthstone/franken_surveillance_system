#![forbid(unsafe_code)]
//! Actual native packet/source fixtures for retained recorder-time parity.

use fss_core::{CanonicalEncode, ContentDigest};
use fss_packet::H264Mode;
use fss_packet::avc::{
    AvcAssemblyStep, AvcPictureGroup, AvcReceiveLimits, AvcReceivePoll, AvcReceiver,
};
use fss_publication::{NeverCancel, SlotName};
use fss_reference::ingest::rtsp_import::RtspImportCodec;
use fss_reference::rtsp::client::replay::ReplayAcceptance;
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording::hevc::PreparedHevcRecording;
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording_archive::ArchiveNamespace;
use fss_reference::rtsp::recording_archive::hevc::HevcArchiveNamespace;
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::rtsp::recording_replay::time::{ReplayTimeLimits, ReplayTimeQuery};
use fss_reference::rtsp::recording_replay::{
    ReplayReceipt, ReplayRequest, ReplayTermination, ReplayWindowProof, publish_replay_receipt,
};
use std::collections::BTreeMap;

use super::{hevc_recording_support, import_support, recording_support};
use import_support::{Fixture, Test};

type Error = Box<dyn std::error::Error>;
type TestResult = Result<(), Error>;

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

enum Original {
    Avc(PreparedRecording),
    Hevc(PreparedHevcRecording),
}
impl Original {
    fn plan(&self) -> &PreparedRecording {
        match self {
            Self::Avc(recording) => recording,
            Self::Hevc(recording) => recording.publication_plan(),
        }
    }
    fn proof(&self, slot: SlotName) -> Test<ReplayWindowProof> {
        Ok(match self {
            Self::Avc(recording) => ReplayWindowProof::from_avc(slot, recording)?,
            Self::Hevc(recording) => ReplayWindowProof::from_hevc(slot, recording)?,
        })
    }
}

/// Three complete native windows: usable, absent, then malformed recorder assertions.
/// HEVC keeps the three trailing parameter NALs in each original as source-only evidence.
pub(super) fn timestamp_fixture(label: &str, codec: RtspImportCodec) -> Test<Fixture> {
    let mut f = Fixture::new(label, codec, 0, true)?;
    let mut originals = Vec::new();
    for ordinal in 0..3 {
        originals.push(match codec {
            RtspImportCodec::Avc => {
                let source = rebuild_avc(
                    recording_support::fixture(921 + ordinal, true)?,
                    |at, bytes| {
                        if at == 0 && ordinal != 1 {
                            stamp(
                                bytes,
                                NTP_SECONDS + ordinal as u32,
                                0,
                                if ordinal == 2 { 1 } else { 0 },
                                7,
                            )?;
                        }
                        Ok(())
                    },
                )?;
                Original::Avc(source.prepare_at(ordinal as u64 * 3_600)?)
            }
            RtspImportCodec::Hevc => {
                let mut packets = hevc_recording_support::packets()?;
                for packet in &mut packets {
                    packet.sequence += ordinal as u64 * 64;
                    packet.received_ns += ordinal as u64 * 64;
                    packet.bytes[2..4].copy_from_slice(&(packet.sequence as u16).to_be_bytes());
                    let time = timestamp(&packet.bytes)? + ordinal as u32 * 36_000;
                    packet.bytes[4..8].copy_from_slice(&time.to_be_bytes());
                    if ordinal != 1 {
                        stamp(
                            &mut packet.bytes,
                            NTP_SECONDS + time / 18_000,
                            0,
                            if ordinal == 2 { 1 } else { 0 },
                            7,
                        )?;
                    }
                }
                let mut timings = hevc_recording_support::timings(2);
                for timing in &mut timings {
                    timing.decode_time += ordinal as u64 * 36_000;
                }
                let recording = hevc_recording_support::prepare(&packets[..8], &timings)?;
                assert_eq!(recording.source_only_nals(), 3);
                Original::Hevc(recording)
            }
        });
    }
    let old_request = f.receipt.request();
    let source_scope = originals
        .first()
        .ok_or("first original")?
        .plan()
        .summary()
        .scope
        .clone();
    let route = ContentDigest::sha256(b"exact timestamped recorder route");
    let base_clock = ContentDigest::sha256(b"explicit timestamped recorder decode clock");
    let mut request = match codec {
        RtspImportCodec::Avc => {
            ReplayRequest::new(source_scope, route, old_request.window(), base_clock)?
        }
        RtspImportCodec::Hevc => {
            ReplayRequest::new_hevc(source_scope, route, old_request.window(), base_clock)?
        }
    };
    request =
        request.with_onvif_source(old_request.onvif_source().ok_or("ONVIF selection")?.clone())?;
    let scope = CatalogScope {
        recording: request.scope().clone(),
        decode_clock: request.decode_clock(),
        time_scale: 90_000,
    };
    let source = f.source.as_mut().ok_or("source")?;
    let mut windows = Vec::new();
    let mut payloads = BTreeMap::new();
    let mut packet_packs = Vec::new();
    let mut media = Vec::new();
    let mut frames = 0;
    for (ordinal, original) in originals.iter().enumerate() {
        let slot = match codec {
            RtspImportCodec::Avc => ArchiveNamespace::new(scope.clone())?.window_slot(ordinal)?,
            RtspImportCodec::Hevc => {
                HevcArchiveNamespace::new(scope.clone())?.window_slot(ordinal)?
            }
        };
        let plan = original.plan();
        let mut publication =
            RecordingPublication::new(plan, source, slot.clone(), plan.byte_len(), 100)?;
        for at in 0..4 {
            assert!(matches!(
                publication.step(at, &NeverCancel)?,
                RecordingProgress::ChildStaged { .. }
            ));
        }
        assert!(matches!(
            publication.step(4, &NeverCancel)?,
            RecordingProgress::Published(_)
        ));
        drop(publication);
        payloads.insert(plan.manifest().root(), plan.manifest().canonical_bytes());
        payloads.extend(
            plan.children()
                .into_iter()
                .map(|(_, digest, bytes)| (digest, bytes.to_vec())),
        );
        packet_packs.push(ContentDigest::sha256(plan.objects().source));
        frames += plan.summary().samples;
        windows.push(original.proof(slot)?);
        if ordinal == 0 {
            media.extend_from_slice(plan.objects().initialization);
        }
        let start = media.len();
        media.extend_from_slice(plan.objects().media);
        assert_eq!(&media[start + 12..start + 16], b"mfhd");
        media[start + 20..start + 24].copy_from_slice(&(ordinal as u32 + 1).to_be_bytes());
    }
    let acceptance = ReplayAcceptance::new(7, request.window(), request.window())?;
    let receipt = ReplayReceipt::prepare(
        request,
        scope.clone(),
        ContentDigest::sha256(b"approved complete timestamped recorder capture"),
        acceptance,
        windows,
        ReplayTermination::ProtocolFailure,
        false,
    )?;
    publish_replay_receipt(&receipt, source, &NeverCancel)?;
    payloads.insert(receipt.root(), receipt.manifest().canonical_bytes());
    payloads.insert(
        ContentDigest::sha256(receipt.metadata_bytes()),
        receipt.metadata_bytes().to_vec(),
    );
    f.originals = payloads;
    f.packet_packs = packet_packs;
    f.frames = frames;
    f.media = media;
    f.request.receipt_root = receipt.root();
    f.request.request_identity = receipt.request().digest();
    f.request.scope = scope;
    f.receipt = receipt;
    Ok(f)
}

pub(super) fn query(f: &Fixture) -> ReplayTimeQuery {
    ReplayTimeQuery {
        codec: f.receipt.request().codec(),
        scope: f.receipt.scope().clone(),
        receipt_root: f.receipt.root(),
        request: f.receipt.request().digest(),
        ntp_era: 0,
        start_ns: UTC_NS,
        end_ns: UTC_NS + 10_000_000_000,
        limits: ReplayTimeLimits::default(),
    }
}

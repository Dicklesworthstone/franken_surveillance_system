#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Real independently scoped AVC/HEVC sessions; only publication and metadata are retained.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_container::TimedAvcPicture;
use fss_core::{CanonicalEncode, ContentDigest, SensorId, StreamId};
use fss_object::{HostSpoolIo, ObjectManifest, SpoolIo, encode_spool_object};
use fss_packet::avc::{AvcReceiveLimits, AvcReceiver, parse_pps, parse_sps};
use fss_packet::{H264Mode, StreamKey};
use fss_publication::{SlotName, root_record_bytes};
use fss_reference::agent_recordings::RecordingQueryCodec;
use fss_reference::agent_recordings::set::RecordingCatalogPin;
use fss_reference::agent_recordings::utc_sessions::{
    RecordingUtcSessionPin, RecordingUtcSessionsError, RecordingUtcSessionsLimits,
    RecordingUtcSessionsQuery, RecordingUtcSessionsRequest, query_recordings_utc_sessions,
};
use fss_reference::rtsp::recording::hevc::{PreparedHevcRecording, prepare_hevc_recording};
use fss_reference::rtsp::recording::{
    PreparedRecording, RecordingPacket, RecordingScope, prepare_recording,
};
use fss_reference::rtsp::recording_catalog::hevc::{HevcCatalogWindow, prepare_hevc_catalog};
use fss_reference::rtsp::recording_catalog::{CatalogScope, CatalogWindow, prepare_catalog};
use fss_reference::rtsp::recording_clock::{
    ClockWindow, RecordingClockCodec, RecordingClockIndex, clock_slot,
};

use crate::{clock_support, collector_support, hevc_recording_support};

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
static NEXT_PATH: AtomicUsize = AtomicUsize::new(0);

pub enum NativeWindow {
    Avc(PreparedRecording),
    Hevc(PreparedHevcRecording),
}
impl NativeWindow {
    pub fn plan(&self) -> &PreparedRecording {
        match self {
            Self::Avc(recording) => recording,
            Self::Hevc(recording) => recording.publication_plan(),
        }
    }
    fn descriptor(&self, slot: SlotName) -> TestResult<ClockWindow> {
        Ok(match self {
            Self::Avc(recording) => ClockWindow::from_avc(slot, recording)?,
            Self::Hevc(recording) => ClockWindow::from_hevc(slot, recording)?,
        })
    }
}

pub struct CatalogData {
    pub slot: SlotName,
    pub manifest: ObjectManifest,
    pub index: Vec<u8>,
}

pub struct SessionData {
    pub codec: RecordingQueryCodec,
    pub scope: CatalogScope,
    pub clock: RecordingClockIndex,
    pub windows: Vec<(SlotName, NativeWindow)>,
    pub catalogs: Vec<CatalogData>,
}

pub struct Fixture {
    pub root: PathBuf,
    pub request: RecordingUtcSessionsRequest,
    pub sessions: Vec<SessionData>,
    pub leaves: BTreeSet<ContentDigest>,
}

impl Fixture {
    pub fn new(
        name: &str,
        codecs: &[RecordingQueryCodec],
        count: usize,
        page_size: usize,
        clocked: &[usize],
    ) -> TestResult<Self> {
        let mut sessions = Vec::new();
        let mut pins = Vec::new();
        let mut leaves = BTreeSet::new();
        for (session_index, codec) in codecs.iter().copied().enumerate() {
            let generation = 1 + session_index as u64;
            let scope = CatalogScope {
                recording: RecordingScope {
                    sensor: SensorId::parse("utc-sessions-fixture")?,
                    stream: StreamId::parse("video")?,
                    generation,
                    anchor: ContentDigest::sha256(
                        format!("session-{generation}-authority").as_bytes(),
                    ),
                    receive_clock: ContentDigest::sha256(
                        format!("session-{generation}-receive").as_bytes(),
                    ),
                },
                decode_clock: ContentDigest::sha256(
                    format!("session-{generation}-decode").as_bytes(),
                ),
                time_scale: if session_index % 2 == 0 {
                    90_000
                } else {
                    60_000
                },
            };
            let admissions = (0..count)
                .map(|ordinal| {
                    30_000_000 + session_index as u64 * 5_000_000 + ordinal as u64 * 500_000
                })
                .collect::<Vec<_>>();
            let mut windows = Vec::new();
            for (ordinal, admission) in admissions.iter().copied().enumerate() {
                let native = match codec {
                    RecordingQueryCodec::Avc => {
                        NativeWindow::Avc(avc_window(&scope, ordinal, admission)?)
                    }
                    RecordingQueryCodec::Hevc => {
                        let mut packets = hevc_recording_support::packets()?;
                        for packet in &mut packets {
                            packet.received_ns = admission;
                        }
                        let mut timings = hevc_recording_support::timings(4);
                        for timing in &mut timings {
                            timing.decode_time += 1000 + 100_000 * ordinal as u64;
                        }
                        NativeWindow::Hevc(prepare_hevc_recording(
                            scope.recording.clone(),
                            &hevc_recording_support::configuration()?,
                            scope.time_scale,
                            &timings,
                            &hevc_recording_support::borrowed(&packets),
                        )?)
                    }
                };
                leaves.extend(native.plan().children().map(|(_, digest, _)| digest));
                windows.push((
                    SlotName::parse(&format!("session-{generation}-window-{ordinal:03}"))?,
                    native,
                ));
            }
            let mut catalogs = Vec::new();
            for first in (0..count).step_by(page_size) {
                let end = count.min(first + page_size);
                catalogs.push(prepare_page(
                    codec,
                    &scope,
                    SlotName::parse(&format!("session-{generation}-page-{first:03}"))?,
                    &windows,
                    &(first..end).collect::<Vec<_>>(),
                )?);
            }
            let mut descriptors = Vec::new();
            let mut brackets = Vec::new();
            for ordinal in clocked {
                let (slot, native) = windows.get(*ordinal).ok_or("clock member ordinal")?;
                descriptors.push(native.descriptor(slot.clone())?);
                brackets.push(clock_support::bracket(admissions[*ordinal]));
            }
            let clock = RecordingClockIndex::prepare(
                scope.clone(),
                clock_codec(codec),
                ContentDigest::sha256(format!("session-{generation}-clock-approval").as_bytes()),
                clock_support::exchange()?,
                clock_support::host(100_000_000),
                &brackets,
                &descriptors,
            )?;
            pins.push(RecordingUtcSessionPin {
                codec,
                scope: scope.clone(),
                catalogs: catalogs
                    .iter()
                    .map(|catalog| RecordingCatalogPin {
                        slot: catalog.slot.clone(),
                        root: catalog.manifest.root(),
                    })
                    .collect(),
                clock_slot: clock_slot(clock_codec(codec), &scope)?,
                clock_root: clock.root(),
            });
            sessions.push(SessionData {
                codec,
                scope,
                clock,
                windows,
                catalogs,
            });
        }
        let root = std::env::temp_dir().join(format!(
            "fss-utc-sessions-{name}-{}-{}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root)?;
        for directory in ["roots", "tombstones", "spool/objects"] {
            fs::create_dir_all(root.join(directory))?;
        }
        let fixture = Self {
            root,
            request: RecordingUtcSessionsRequest {
                sessions: pins,
                interval: 0..1,
                max_windows: 64,
                max_hydration_bytes: 256 * 1024 * 1024,
            },
            sessions,
            leaves,
        };
        for (session, pin) in fixture.sessions.iter().zip(&fixture.request.sessions) {
            for catalog in &session.catalogs {
                fixture.put(&catalog.index)?;
                fixture.publish(&catalog.slot, &catalog.manifest)?;
            }
            for (slot, native) in &session.windows {
                fixture.publish(slot, native.plan().manifest())?;
            }
            fixture.put(session.clock.index_bytes())?;
            fixture.publish(&pin.clock_slot, session.clock.manifest())?;
        }
        Ok(fixture)
    }

    pub fn object(&self, digest: ContentDigest) -> PathBuf {
        self.root
            .join("spool/objects")
            .join(digest.to_text().trim_start_matches("sha256:"))
    }
    pub fn record(&self, slot: &SlotName) -> PathBuf {
        self.root
            .join("roots")
            .join(format!("{}.root", slot.as_str()))
    }
    pub fn tombstone(&self, digest: ContentDigest) -> PathBuf {
        self.root
            .join("tombstones")
            .join(format!("{}.tomb", digest.to_text().replacen(':', "-", 1)))
    }
    pub fn put(&self, bytes: &[u8]) -> TestResult {
        let digest = ContentDigest::sha256(bytes);
        fs::write(self.object(digest), encode_spool_object(digest, bytes)?)?;
        Ok(())
    }
    pub fn publish(&self, slot: &SlotName, manifest: &ObjectManifest) -> TestResult {
        self.put(&manifest.canonical_bytes())?;
        fs::write(
            self.record(slot),
            root_record_bytes(slot, manifest.root(), manifest.children().len())?,
        )?;
        Ok(())
    }
    pub fn publish_catalog(
        &self,
        session: usize,
        name: &str,
        members: &[usize],
    ) -> TestResult<RecordingCatalogPin> {
        let source = &self.sessions[session];
        let page = prepare_page(
            source.codec,
            &source.scope,
            SlotName::parse(name)?,
            &source.windows,
            members,
        )?;
        self.put(&page.index)?;
        self.publish(&page.slot, &page.manifest)?;
        Ok(RecordingCatalogPin {
            slot: page.slot,
            root: page.manifest.root(),
        })
    }
    pub fn query(&self) -> Result<RecordingUtcSessionsQuery, RecordingUtcSessionsError> {
        self.query_with(&HostSpoolIo, RecordingUtcSessionsLimits::default(), &|| {
            false
        })
    }
    pub fn query_with(
        &self,
        io: &dyn SpoolIo,
        limits: RecordingUtcSessionsLimits,
        cancelled: &(impl Fn() -> bool + Sync),
    ) -> Result<RecordingUtcSessionsQuery, RecordingUtcSessionsError> {
        query_recordings_utc_sessions(io, &self.root, &self.request, limits, cancelled)
    }
    pub fn first_pass_opens(&self) -> usize {
        self.request
            .sessions
            .iter()
            .enumerate()
            .map(|(index, pin)| 3 * pin.catalogs.len() + 2 * self.sessions[index].windows.len() + 3)
            .sum()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub fn clock_codec(codec: RecordingQueryCodec) -> RecordingClockCodec {
    match codec {
        RecordingQueryCodec::Avc => RecordingClockCodec::Avc,
        RecordingQueryCodec::Hevc => RecordingClockCodec::Hevc,
    }
}

fn prepare_page(
    codec: RecordingQueryCodec,
    scope: &CatalogScope,
    slot: SlotName,
    windows: &[(SlotName, NativeWindow)],
    members: &[usize],
) -> TestResult<CatalogData> {
    let (manifest, index) = match codec {
        RecordingQueryCodec::Avc => {
            let entries = members
                .iter()
                .map(|ordinal| CatalogWindow {
                    slot: &windows[*ordinal].0,
                    recording: windows[*ordinal].1.plan(),
                })
                .collect::<Vec<_>>();
            let catalog = prepare_catalog(scope.clone(), &entries)?;
            (catalog.manifest().clone(), catalog.index_bytes().to_vec())
        }
        RecordingQueryCodec::Hevc => {
            let mut entries = Vec::new();
            for ordinal in members {
                let (slot, NativeWindow::Hevc(recording)) = &windows[*ordinal] else {
                    return Err("HEVC fixture family".into());
                };
                entries.push(HevcCatalogWindow { slot, recording });
            }
            let catalog = prepare_hevc_catalog(scope.clone(), &entries)?;
            (catalog.manifest().clone(), catalog.index_bytes().to_vec())
        }
    };
    Ok(CatalogData {
        slot,
        manifest,
        index,
    })
}

fn avc_window(
    scope: &CatalogScope,
    ordinal: usize,
    admission: u64,
) -> TestResult<PreparedRecording> {
    let raw = collector_support::nals();
    let limits = AvcReceiveLimits::default();
    let sps = parse_sps(raw[0], limits.syntax)?;
    let pps = parse_pps(raw[1], &sps, limits.syntax)?;
    let key = StreamKey {
        ingress: 31,
        generation: scope.recording.generation,
        ssrc: 7,
    };
    let mut receiver = AvcReceiver::new(key, 96, H264Mode::NonInterleaved, limits, (sps, pps))?;
    let timestamp = 90_000 + ordinal as u32 * 3600;
    receiver.ingest(
        key,
        &collector_support::packet(0, timestamp, false, raw[0]),
        0,
    )?;
    let idr = raw
        .iter()
        .find(|nal| nal[0] & 31 == 5)
        .ok_or("IDR fixture")?;
    let wire = collector_support::packet(1, timestamp, true, idr);
    receiver.ingest(key, &wire, 1)?;
    let pictures = collector_support::drain(&mut receiver, 1)?;
    if pictures.len() != 1 {
        return Err("fixture requires one marker-bounded picture".into());
    }
    Ok(prepare_recording(
        scope.recording.clone(),
        scope.time_scale,
        &[TimedAvcPicture {
            picture: &pictures[0],
            decode_time: 3600 + 7200 * ordinal as u64,
            duration: 3600,
            composition_offset: 0,
        }],
        &[RecordingPacket {
            sequence: 1,
            received_ns: admission,
            bytes: &wire,
        }],
    )?)
}

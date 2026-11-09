#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Real native windows; the archive fixture deliberately retains metadata only.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_core::{CanonicalEncode, ContentDigest};
use fss_object::{HostSpoolIo, ObjectManifest, encode_spool_object};
use fss_publication::{SlotName, root_record_bytes};
use fss_reference::agent_recordings::RecordingQueryCodec;
use fss_reference::agent_recordings::utc::{
    RecordingUtcQuery, RecordingUtcQueryError, RecordingUtcQueryLimits, RecordingUtcQueryRequest,
    query_recordings_utc,
};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording::hevc::{PreparedHevcRecording, prepare_hevc_recording};
use fss_reference::rtsp::recording_catalog::hevc::{HevcCatalogWindow, prepare_hevc_catalog};
use fss_reference::rtsp::recording_catalog::{CatalogScope, CatalogWindow, prepare_catalog};
use fss_reference::rtsp::recording_clock::{
    ClockWindow, RecordingClockCodec, RecordingClockIndex, clock_slot,
};

use crate::{clock_support, hevc_catalog_support, hevc_recording_support};

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
static NEXT_PATH: AtomicUsize = AtomicUsize::new(0);
pub const ADMISSIONS: [u64; 3] = [40_000_000, 60_000_000, 80_000_000];

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
    pub fn descriptor(&self, slot: SlotName) -> TestResult<ClockWindow> {
        Ok(match self {
            Self::Avc(recording) => ClockWindow::from_avc(slot, recording)?,
            Self::Hevc(recording) => ClockWindow::from_hevc(slot, recording)?,
        })
    }
}

pub struct Fixture {
    pub root: PathBuf,
    pub request: RecordingUtcQueryRequest,
    pub catalog: ObjectManifest,
    pub catalog_bytes: Vec<u8>,
    pub clock: RecordingClockIndex,
    pub windows: Vec<(SlotName, NativeWindow)>,
    pub leaves: BTreeSet<ContentDigest>,
}
impl Fixture {
    pub fn new(name: &str, codec: RecordingQueryCodec, clocked: &[usize]) -> TestResult<Self> {
        Self::with_admissions(name, codec, &ADMISSIONS, clocked)
    }

    pub fn with_admissions(
        name: &str,
        codec: RecordingQueryCodec,
        admissions: &[u64],
        clocked: &[usize],
    ) -> TestResult<Self> {
        let scope = match codec {
            RecordingQueryCodec::Avc => clock_support::catalog_scope()?,
            RecordingQueryCodec::Hevc => hevc_catalog_support::scope()?,
        };
        let mut windows = Vec::new();
        for (ordinal, admission) in admissions.iter().copied().enumerate() {
            let native = match codec {
                RecordingQueryCodec::Avc => NativeWindow::Avc(clock_support::window(
                    1 + 2 * ordinal as u64,
                    3600 + 7200 * ordinal as u64,
                    &[admission],
                )?),
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
            windows.push((SlotName::parse(&format!("window-{ordinal}"))?, native));
        }
        let (catalog, catalog_bytes) = match codec {
            RecordingQueryCodec::Avc => {
                let entries: Vec<_> = windows
                    .iter()
                    .map(|(slot, window)| CatalogWindow {
                        slot,
                        recording: window.plan(),
                    })
                    .collect();
                let catalog = prepare_catalog(scope.clone(), &entries)?;
                (catalog.manifest().clone(), catalog.index_bytes().to_vec())
            }
            RecordingQueryCodec::Hevc => {
                let mut entries = Vec::new();
                for (slot, window) in &windows {
                    let NativeWindow::Hevc(recording) = window else {
                        return Err("HEVC fixture family".into());
                    };
                    entries.push(HevcCatalogWindow { slot, recording });
                }
                let catalog = prepare_hevc_catalog(scope.clone(), &entries)?;
                (catalog.manifest().clone(), catalog.index_bytes().to_vec())
            }
        };
        let clock_codec = clock_codec(codec);
        let mut descriptors = Vec::new();
        let mut brackets = Vec::new();
        for ordinal in clocked {
            let (slot, window) = windows.get(*ordinal).ok_or("clock member ordinal")?;
            descriptors.push(window.descriptor(slot.clone())?);
            brackets.push(clock_support::bracket(admissions[*ordinal]));
        }
        let clock = RecordingClockIndex::prepare(
            scope.clone(),
            clock_codec,
            clock_support::approval(),
            clock_support::exchange()?,
            clock_support::host(100_000_000),
            &brackets,
            &descriptors,
        )?;
        let first_interval = clock
            .windows()
            .first()
            .ok_or("clock first row")?
            .utc_interval();
        let root = std::env::temp_dir().join(format!(
            "fss-agent-recordings-utc-{name}-{}-{}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root)?;
        for directory in ["roots", "tombstones", "spool/objects"] {
            fs::create_dir_all(root.join(directory))?;
        }
        let leaves = windows
            .iter()
            .flat_map(|(_, window)| window.plan().children().map(|(_, digest, _)| digest))
            .collect();
        let request = RecordingUtcQueryRequest {
            codec,
            scope: scope.clone(),
            catalog_slot: SlotName::parse("recording-catalog")?,
            catalog_root: catalog.root(),
            clock_slot: clock_slot(clock_codec, &scope)?,
            clock_root: clock.root(),
            interval: first_interval.earliest_ns..first_interval.latest_ns + 1,
            max_windows: 64,
            max_hydration_bytes: 256 * 1024 * 1024,
        };
        let fixture = Self {
            root,
            request,
            catalog,
            catalog_bytes,
            clock,
            windows,
            leaves,
        };
        fixture.put(&fixture.catalog_bytes)?;
        fixture.publish(&fixture.request.catalog_slot, &fixture.catalog)?;
        fixture.put(fixture.clock.index_bytes())?;
        fixture.publish(&fixture.request.clock_slot, fixture.clock.manifest())?;
        for (slot, window) in &fixture.windows {
            fixture.publish(slot, window.plan().manifest())?;
        }
        Ok(fixture)
    }

    pub fn object(&self, digest: ContentDigest) -> PathBuf {
        self.root
            .join("spool/objects")
            .join(digest.to_text().trim_start_matches("sha256:"))
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
            self.root
                .join("roots")
                .join(format!("{}.root", slot.as_str())),
            root_record_bytes(slot, manifest.root(), manifest.children().len())?,
        )?;
        Ok(())
    }
    pub fn query(&self) -> Result<RecordingUtcQuery, RecordingUtcQueryError> {
        query_recordings_utc(
            &HostSpoolIo,
            &self.root,
            &self.request,
            RecordingUtcQueryLimits::default(),
            &|| false,
        )
    }
    pub fn replace_clock_metadata(&mut self, bytes: &[u8]) -> TestResult {
        let old = self
            .clock
            .manifest()
            .metadata_digest()
            .ok_or("clock metadata")?;
        let manifest = ObjectManifest::new(
            self.clock.manifest().kind(),
            self.clock
                .manifest()
                .children()
                .iter()
                .copied()
                .filter(|digest| *digest != old),
            Some(ContentDigest::sha256(bytes)),
        )?;
        self.put(bytes)?;
        self.publish(&self.request.clock_slot, &manifest)?;
        self.request.clock_root = manifest.root();
        Ok(())
    }
    pub fn scope(&self) -> &CatalogScope {
        &self.request.scope
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

pub fn rechecksum(bytes: &mut [u8]) -> TestResult {
    let body = bytes
        .len()
        .checked_sub(33)
        .ok_or("clock checksum trailer")?;
    let digest = ContentDigest::sha256(&bytes[..body]);
    bytes[body] = 1;
    bytes[body + 1..].copy_from_slice(&digest.bytes());
    Ok(())
}

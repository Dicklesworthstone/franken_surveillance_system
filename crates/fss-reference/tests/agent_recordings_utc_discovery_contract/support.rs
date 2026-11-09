#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Canonically named native capture pages and one retained clock, without source payloads.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_core::{CanonicalEncode, ContentDigest};
use fss_object::{HostSpoolIo, ObjectManifest, SpoolIo, encode_spool_object};
use fss_publication::{SlotName, root_record_bytes};
use fss_reference::agent_recordings::RecordingQueryCodec;
use fss_reference::agent_recordings::utc_discover::{
    RecordingUtcDiscoveryError, RecordingUtcDiscoveryLimits, RecordingUtcDiscoveryQuery,
    RecordingUtcDiscoveryRequest, discover_recordings_utc,
};
use fss_reference::rtsp::recording::hevc::prepare_hevc_recording;
use fss_reference::rtsp::recording_archive::{
    AvcArchiveCodec, CodecArchiveNamespace, HevcArchiveCodec,
};
use fss_reference::rtsp::recording_catalog::hevc::{HevcCatalogWindow, prepare_hevc_catalog};
use fss_reference::rtsp::recording_catalog::{CatalogScope, CatalogWindow, prepare_catalog};
use fss_reference::rtsp::recording_clock::{RecordingClockIndex, clock_slot};

pub use crate::utc_support::TestResult;
use crate::utc_support::{NativeWindow, clock_codec};
use crate::{clock_support, hevc_catalog_support, hevc_recording_support};

static NEXT_PATH: AtomicUsize = AtomicUsize::new(0);

pub struct CatalogData {
    pub slot: SlotName,
    pub manifest: ObjectManifest,
    pub index: Vec<u8>,
}

pub struct Fixture {
    pub root: PathBuf,
    pub request: RecordingUtcDiscoveryRequest,
    pub clock: RecordingClockIndex,
    pub windows: Vec<(SlotName, NativeWindow)>,
    pub catalogs: Vec<CatalogData>,
    pub leaves: BTreeSet<ContentDigest>,
}

impl Fixture {
    pub fn new(
        name: &str,
        codec: RecordingQueryCodec,
        count: usize,
        page_size: usize,
        clocked: &[usize],
    ) -> TestResult<Self> {
        let scope = match codec {
            RecordingQueryCodec::Avc => clock_support::catalog_scope()?,
            RecordingQueryCodec::Hevc => hevc_catalog_support::scope()?,
        };
        let mut windows = Vec::new();
        let admissions = (0..count)
            .map(|ordinal| 30_000_000 + 500_000 * ordinal as u64)
            .collect::<Vec<_>>();
        for (ordinal, admission) in admissions.iter().copied().enumerate() {
            let window = match codec {
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
            windows.push((namespace_slot(codec, &scope, false, ordinal)?, window));
        }
        let mut catalogs = Vec::new();
        for first in (0..count).step_by(page_size) {
            let end = count.min(first + page_size);
            let (manifest, index) = match codec {
                RecordingQueryCodec::Avc => {
                    let entries = windows[first..end]
                        .iter()
                        .map(|(slot, native)| CatalogWindow {
                            slot,
                            recording: native.plan(),
                        })
                        .collect::<Vec<_>>();
                    let catalog = prepare_catalog(scope.clone(), &entries)?;
                    (catalog.manifest().clone(), catalog.index_bytes().to_vec())
                }
                RecordingQueryCodec::Hevc => {
                    let mut entries = Vec::new();
                    for (slot, native) in &windows[first..end] {
                        let NativeWindow::Hevc(recording) = native else {
                            return Err("HEVC fixture family".into());
                        };
                        entries.push(HevcCatalogWindow { slot, recording });
                    }
                    let catalog = prepare_hevc_catalog(scope.clone(), &entries)?;
                    (catalog.manifest().clone(), catalog.index_bytes().to_vec())
                }
            };
            catalogs.push(CatalogData {
                slot: namespace_slot(codec, &scope, true, first)?,
                manifest,
                index,
            });
        }
        let mut descriptors = Vec::new();
        let mut brackets = Vec::new();
        for ordinal in clocked {
            let (slot, window) = windows.get(*ordinal).ok_or("clock member ordinal")?;
            descriptors.push(window.descriptor(slot.clone())?);
            brackets.push(clock_support::bracket(admissions[*ordinal]));
        }
        let clock = RecordingClockIndex::prepare(
            scope.clone(),
            clock_codec(codec),
            clock_support::approval(),
            clock_support::exchange()?,
            clock_support::host(100_000_000),
            &brackets,
            &descriptors,
        )?;
        let last = clock
            .windows()
            .last()
            .ok_or("nonempty clock")?
            .utc_interval();
        let root = std::env::temp_dir().join(format!(
            "fss-utc-discovery-{name}-{}-{}",
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
        let request = RecordingUtcDiscoveryRequest {
            codec,
            scope: scope.clone(),
            clock_slot: clock_slot(clock_codec(codec), &scope)?,
            clock_root: clock.root(),
            interval: last.latest_ns..last.latest_ns + 1,
            max_windows: 64,
            max_hydration_bytes: 256 * 1024 * 1024,
        };
        let fixture = Self {
            root,
            request,
            clock,
            windows,
            catalogs,
            leaves,
        };
        for catalog in &fixture.catalogs {
            fixture.put(&catalog.index)?;
            fixture.publish(&catalog.slot, &catalog.manifest)?;
        }
        for (slot, window) in &fixture.windows {
            fixture.publish(slot, window.plan().manifest())?;
        }
        fixture.put(fixture.clock.index_bytes())?;
        fixture.publish(&fixture.request.clock_slot, fixture.clock.manifest())?;
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

    pub fn query(&self) -> Result<RecordingUtcDiscoveryQuery, RecordingUtcDiscoveryError> {
        self.query_with(
            &HostSpoolIo,
            RecordingUtcDiscoveryLimits::default(),
            &|| false,
        )
    }

    pub fn query_with(
        &self,
        io: &dyn SpoolIo,
        limits: RecordingUtcDiscoveryLimits,
        cancelled: &(impl Fn() -> bool + Sync),
    ) -> Result<RecordingUtcDiscoveryQuery, RecordingUtcDiscoveryError> {
        discover_recordings_utc(io, &self.root, &self.request, limits, cancelled)
    }

    pub fn first_pass_opens(&self) -> usize {
        // Namespace root records, catalog manifests/indexes, member publications, clock pair.
        3 * self.windows.len() + 4 * self.catalogs.len() + 3
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub fn namespace_slot(
    codec: RecordingQueryCodec,
    scope: &CatalogScope,
    page: bool,
    ordinal: usize,
) -> TestResult<SlotName> {
    Ok(match codec {
        RecordingQueryCodec::Avc => {
            let namespace = CodecArchiveNamespace::<AvcArchiveCodec>::new(scope.clone())?;
            if page {
                namespace.page_slot(ordinal)?
            } else {
                namespace.window_slot(ordinal)?
            }
        }
        RecordingQueryCodec::Hevc => {
            let namespace = CodecArchiveNamespace::<HevcArchiveCodec>::new(scope.clone())?;
            if page {
                namespace.page_slot(ordinal)?
            } else {
                namespace.window_slot(ordinal)?
            }
        }
    })
}

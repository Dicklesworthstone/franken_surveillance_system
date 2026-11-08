#![forbid(unsafe_code)]
//! Metadata-only native archive discovery, including pages beyond the selected output bound.

mod collector_support;
mod hevc_catalog_support;
mod hevc_recording_support;
mod recording_support;

use std::collections::BTreeSet;
use std::fs;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use fss_core::{CanonicalEncode, ContentDigest};
use fss_object::{
    HostSpoolIo, ObjectManifest, RecordingSpoolIo, SpoolIo, SpoolIoCall, encode_spool_object,
};
use fss_publication::custody_audit::CustodyAuditError;
use fss_publication::custody_audit::pinned_metadata::PinnedMetadataError;
use fss_publication::{SlotName, root_record_bytes};
use fss_reference::agent_recordings::RecordingQueryCodec;
use fss_reference::agent_recordings::discover::{
    RecordingDiscoveryError, RecordingDiscoveryLimits, RecordingDiscoveryQuery,
    RecordingDiscoveryRequest, discover_recordings,
};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording_archive::{
    AvcArchiveCodec, CodecArchiveNamespace, HevcArchiveCodec,
};
use fss_reference::rtsp::recording_catalog::hevc::{HevcCatalogWindow, prepare_hevc_catalog};
use fss_reference::rtsp::recording_catalog::{
    CatalogError, CatalogScope, CatalogWindow, prepare_catalog,
};
use fss_reference::rtsp::recording_collector::CollectorLimits;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct WindowData {
    slot: SlotName,
    manifest: ObjectManifest,
    interval: Range<u64>,
    bytes: usize,
}
struct CatalogData {
    slot: SlotName,
    manifest: ObjectManifest,
    index: Vec<u8>,
}
struct Fixture {
    root: PathBuf,
    request: RecordingDiscoveryRequest,
    windows: Vec<WindowData>,
    catalogs: Vec<CatalogData>,
    leaves: BTreeSet<ContentDigest>,
}
impl Fixture {
    fn new(
        name: &str,
        codec: RecordingQueryCodec,
        count: usize,
        page_size: usize,
    ) -> TestResult<Self> {
        let scope = match codec {
            RecordingQueryCodec::Avc => CatalogScope {
                recording: collector_support::scope()?,
                decode_clock: ContentDigest::sha256(b"discovery-native-decode-clock"),
                time_scale: 90_000,
            },
            RecordingQueryCodec::Hevc => hevc_catalog_support::scope()?,
        };
        let slots = (0..count)
            .map(|ordinal| namespace_slot(codec, &scope, false, ordinal))
            .collect::<TestResult<Vec<_>>>()?;
        let mut catalogs = Vec::new();
        let mut windows = Vec::new();
        let mut leaves = BTreeSet::new();
        match codec {
            RecordingQueryCodec::Avc => {
                let recordings = (0..count)
                    .map(|ordinal| {
                        avc_window(1 + 2 * ordinal as u64, 1000 + 10_000 * ordinal as u64)
                    })
                    .collect::<TestResult<Vec<_>>>()?;
                for first in (0..count).step_by(page_size) {
                    let end = count.min(first + page_size);
                    let members = (first..end)
                        .map(|ordinal| CatalogWindow {
                            slot: &slots[ordinal],
                            recording: &recordings[ordinal],
                        })
                        .collect::<Vec<_>>();
                    let catalog = prepare_catalog(scope.clone(), &members)?;
                    catalogs.push(CatalogData {
                        slot: namespace_slot(codec, &scope, true, first)?,
                        manifest: catalog.manifest().clone(),
                        index: catalog.index_bytes().to_vec(),
                    });
                }
                for (slot, recording) in slots.into_iter().zip(&recordings) {
                    windows.push(WindowData {
                        slot,
                        manifest: recording.manifest().clone(),
                        interval: recording.summary().decode_interval.clone(),
                        bytes: recording.byte_len(),
                    });
                    leaves.extend(recording.children().map(|(_, digest, _)| digest));
                }
            }
            RecordingQueryCodec::Hevc => {
                let recordings = (0..count)
                    .map(|ordinal| hevc_catalog_support::window(1000 + 100_000 * ordinal as u64))
                    .collect::<TestResult<Vec<_>>>()?;
                for first in (0..count).step_by(page_size) {
                    let end = count.min(first + page_size);
                    let members = (first..end)
                        .map(|ordinal| HevcCatalogWindow {
                            slot: &slots[ordinal],
                            recording: &recordings[ordinal],
                        })
                        .collect::<Vec<_>>();
                    let catalog = prepare_hevc_catalog(scope.clone(), &members)?;
                    catalogs.push(CatalogData {
                        slot: namespace_slot(codec, &scope, true, first)?,
                        manifest: catalog.manifest().clone(),
                        index: catalog.index_bytes().to_vec(),
                    });
                }
                for (slot, recording) in slots.into_iter().zip(&recordings) {
                    windows.push(WindowData {
                        slot,
                        manifest: recording.manifest().clone(),
                        interval: recording.summary().decode_interval.clone(),
                        bytes: recording.byte_len(),
                    });
                    leaves.extend(
                        recording
                            .publication_plan()
                            .children()
                            .map(|(_, digest, _)| digest),
                    );
                }
            }
        }

        let mut root = None;
        for suffix in 0..64 {
            let candidate = std::env::temp_dir().join(format!(
                "fss-agent-recording-discovery-{name}-{}-{suffix}",
                std::process::id(),
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => {
                    root = Some(candidate);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        let root = root.ok_or("temporary fixture names exhausted")?;
        for directory in ["roots", "tombstones", "spool/objects"] {
            fs::create_dir_all(root.join(directory))?;
        }
        let interval = 0..windows
            .last()
            .map_or(1000, |window| window.interval.end + 1000);
        let fixture = Self {
            root,
            windows,
            catalogs,
            leaves,
            request: RecordingDiscoveryRequest {
                codec,
                scope,
                interval,
                max_windows: 64,
                max_hydration_bytes: 256 * 1024 * 1024,
            },
        };
        for catalog in &fixture.catalogs {
            fixture.put(&catalog.index)?;
            fixture.publish(&catalog.slot, &catalog.manifest)?;
        }
        for window in &fixture.windows {
            fixture.publish(&window.slot, &window.manifest)?;
        }
        Ok(fixture)
    }

    fn object(&self, digest: ContentDigest) -> PathBuf {
        self.root
            .join("spool/objects")
            .join(digest.to_text().trim_start_matches("sha256:"))
    }

    fn record(&self, slot: &SlotName) -> PathBuf {
        self.root
            .join("roots")
            .join(format!("{}.root", slot.as_str()))
    }

    fn put(&self, bytes: &[u8]) -> TestResult {
        let digest = ContentDigest::sha256(bytes);
        fs::write(self.object(digest), encode_spool_object(digest, bytes)?)?;
        Ok(())
    }

    fn publish(&self, slot: &SlotName, manifest: &ObjectManifest) -> TestResult {
        self.put(&manifest.canonical_bytes())?;
        fs::write(
            self.record(slot),
            root_record_bytes(slot, manifest.root(), manifest.children().len())?,
        )?;
        Ok(())
    }

    fn query(&self) -> Result<RecordingDiscoveryQuery, RecordingDiscoveryError> {
        self.with_limits(RecordingDiscoveryLimits::default())
    }

    fn with_limits(
        &self,
        limits: RecordingDiscoveryLimits,
    ) -> Result<RecordingDiscoveryQuery, RecordingDiscoveryError> {
        self.query_with(&HostSpoolIo, limits, &|| false)
    }

    fn query_with(
        &self,
        io: &dyn SpoolIo,
        limits: RecordingDiscoveryLimits,
        cancelled: &(impl Fn() -> bool + Sync),
    ) -> Result<RecordingDiscoveryQuery, RecordingDiscoveryError> {
        discover_recordings(io, &self.root, &self.request, limits, cancelled)
    }

    fn namespace_prefix(&self) -> TestResult<String> {
        Ok(match self.request.codec {
            RecordingQueryCodec::Avc => {
                CodecArchiveNamespace::<AvcArchiveCodec>::new(self.request.scope.clone())?
                    .prefix()
                    .to_owned()
            }
            RecordingQueryCodec::Hevc => {
                CodecArchiveNamespace::<HevcArchiveCodec>::new(self.request.scope.clone())?
                    .prefix()
                    .to_owned()
            }
        })
    }

    fn initial_root_reads(&self) -> u64 {
        (self.windows.len() + self.catalogs.len()) as u64
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn namespace_slot(
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

fn avc_window(sequence: u64, decode_time: u64) -> TestResult<PreparedRecording> {
    let mut collector = collector_support::collector(CollectorLimits::default())?;
    let sample = collector_support::sample(sequence, 90_000 + sequence as u32 * 3600, true, false)?;
    sample.source(&mut collector, 1)?;
    collector_support::accepted(collector.push_picture(sample.timed(decode_time), 1))?;
    collector.seal(2)?;
    collector
        .take_ready()
        .ok_or_else(|| "missing AVC window".into())
}

#[test]
fn normal_avc_and_hevc_archives_exceed_one_page_without_hydrating_payloads() -> TestResult {
    for codec in [RecordingQueryCodec::Avc, RecordingQueryCodec::Hevc] {
        let mut fixture = Fixture::new(&format!("large-{}", codec.as_str()), codec, 130, 64)?;
        fixture.request.interval =
            fixture.windows[63].interval.start + 1..fixture.windows[64].interval.end - 1;
        fixture.request.max_windows = 2;
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let query = fixture.query_with(&io, RecordingDiscoveryLimits::default(), &|| false)?;
        assert_eq!(query.scanned_windows, 130);
        assert_eq!(query.catalogs.len(), 3);
        assert_eq!(
            query
                .catalogs
                .iter()
                .map(|catalog| catalog.scanned_windows)
                .collect::<Vec<_>>(),
            [64, 64, 2]
        );
        assert_eq!(query.scanned_root_entries, 133);
        assert_eq!(query.read_usage.pinned_roots, 133);
        assert_eq!(query.read_usage.metadata_objects, 136);
        assert_eq!(query.rows.len(), 2);
        for (selected, archive_ordinal) in [63, 64].into_iter().enumerate() {
            let row = &query.rows[selected];
            let window = &fixture.windows[archive_ordinal];
            assert_eq!(row.entry.slot(), &window.slot);
            assert_eq!(row.entry.root(), window.manifest.root());
            assert_eq!(row.locations.len(), 1);
            let location = row.locations[0];
            assert_eq!(location.catalog_index, archive_ordinal / 64);
            assert_eq!(location.ordinal, archive_ordinal % 64);
            assert_eq!(
                location.catalog_root,
                query.catalogs[location.catalog_index].pin.root
            );
        }
        assert_eq!(
            query.rows[0].overlap,
            fixture.request.interval.start..fixture.windows[63].interval.end
        );
        assert_eq!(
            query.rows[1].overlap,
            fixture.windows[64].interval.start..fixture.request.interval.end
        );
        assert_eq!(
            query.indexed_gaps,
            vec![fixture.windows[63].interval.end..fixture.windows[64].interval.start]
        );
        assert_eq!(
            query.quoted_hydration_bytes,
            (fixture.windows[63].bytes + fixture.windows[64].bytes) as u64
        );
        assert!(
            query
                .reference_digests
                .contains(&fixture.windows[129].manifest.root())
        );
        for leaf in &fixture.leaves {
            assert!(query.reference_digests.contains(leaf));
            assert!(!fixture.object(*leaf).exists());
        }
        for leaf in fixture.leaves.iter().take(5) {
            fs::write(
                fixture.object(*leaf),
                b"unread original or per-window metadata",
            )?;
        }
        assert_eq!(fixture.query()?, query);
        assert!(io.is_read_only());
        assert_eq!(io.call_count(SpoolIoCall::ReadDir), 2);
        assert_eq!(query.read_usage.io_calls, io.calls().len() as u64);
        assert!(!fixture.root.join("LOCK").exists());
    }
    Ok(())
}

#[test]
fn filesystem_path_and_directory_order_do_not_change_inventory_or_selection() -> TestResult {
    let first = Fixture::new("ordering-first", RecordingQueryCodec::Avc, 3, 2)?;
    let second = Fixture::new("ordering-second", RecordingQueryCodec::Avc, 3, 2)?;
    let baseline = first.query()?;
    let mut records = fs::read_dir(second.root.join("roots"))?
        .map(|entry| {
            let path = entry?.path();
            Ok((path.clone(), fs::read(path)?))
        })
        .collect::<Result<Vec<_>, std::io::Error>>()?;
    records.sort_by(|left, right| right.0.cmp(&left.0));
    for (path, _) in &records {
        fs::remove_file(path)?;
    }
    for (path, bytes) in records {
        fs::write(path, bytes)?;
    }
    assert_eq!(second.query()?, baseline);
    Ok(())
}

#[test]
fn empty_namespace_is_explicit_and_another_source_is_not_inferred() -> TestResult {
    let fixture = Fixture::new("empty", RecordingQueryCodec::Avc, 0, 64)?;
    let empty = fixture.query()?;
    assert!(
        empty.catalogs.is_empty() && empty.rows.is_empty() && empty.reference_digests.is_empty()
    );
    assert_eq!(empty.indexed_gaps, vec![fixture.request.interval.clone()]);
    assert_eq!(empty.quoted_hydration_bytes, 0);
    assert_eq!(empty.scanned_windows, 0);
    assert_eq!(empty.read_usage.pinned_roots, 0);
    let another = Fixture::new("different-source", RecordingQueryCodec::Avc, 3, 2)?;
    let mut request = another.request.clone();
    request.scope.recording.generation += 1;
    let query = discover_recordings(
        &HostSpoolIo,
        &another.root,
        &request,
        RecordingDiscoveryLimits::default(),
        &|| false,
    )?;
    assert!(query.rows.is_empty());
    assert_eq!(query.indexed_gaps, vec![request.interval.clone()]);
    assert_eq!(query.scanned_root_entries, 5);
    assert_ne!(query.namespace_digest, another.query()?.namespace_digest);
    assert!(query.reference_digests.is_empty());
    Ok(())
}

#[test]
fn unrelated_pending_and_malformed_roots_are_not_interpreted_but_are_charged() -> TestResult {
    let fixture = Fixture::new("unrelated", RecordingQueryCodec::Avc, 3, 2)?;
    let baseline = fixture.query()?;
    for name in ["other.root.tmp", "not-a-slot-name", "foreign.root"] {
        fs::write(
            fixture.root.join("roots").join(name),
            b"not valid selected metadata",
        )?;
    }
    let query = fixture.query()?;
    assert_eq!(query.request_digest, baseline.request_digest);
    assert_eq!(query.inventory_digest, baseline.inventory_digest);
    assert_eq!(query.decision_digest, baseline.decision_digest);
    assert_eq!(query.rows, baseline.rows);
    assert_eq!(query.reference_digests, baseline.reference_digests);
    assert_eq!(
        query.scanned_root_entries,
        baseline.scanned_root_entries + 3
    );
    assert!(query.read_usage.io_calls > baseline.read_usage.io_calls);
    assert_eq!(query.read_usage.read_bytes, baseline.read_usage.read_bytes);
    let limits = RecordingDiscoveryLimits {
        max_scan_roots: baseline.scanned_root_entries,
        ..RecordingDiscoveryLimits::default()
    };
    assert!(fixture.with_limits(limits).is_err());
    Ok(())
}

#[test]
fn unseen_window_tail_refuses_even_when_the_requested_interval_is_empty_of_matches() -> TestResult {
    for codec in [RecordingQueryCodec::Avc, RecordingQueryCodec::Hevc] {
        let mut fixture = Fixture::new(&format!("tail-{}", codec.as_str()), codec, 3, 2)?;
        fixture.request.interval = 0..1;
        assert!(fixture.query()?.rows.is_empty());
        fs::remove_file(fixture.record(&fixture.catalogs[1].slot))?;
        assert_eq!(
            fixture.query(),
            Err(RecordingDiscoveryError::UnindexedWindows)
        );
    }
    let fixture = Fixture::new("no-pages", RecordingQueryCodec::Avc, 2, 2)?;
    fs::remove_file(fixture.record(&fixture.catalogs[0].slot))?;
    assert_eq!(
        fixture.query(),
        Err(RecordingDiscoveryError::UnindexedWindows)
    );
    Ok(())
}

#[test]
fn holes_missing_first_pages_and_overlapping_page_positions_refuse() -> TestResult {
    let fixture = Fixture::new("window-hole", RecordingQueryCodec::Avc, 3, 2)?;
    fs::remove_file(fixture.record(&fixture.windows[1].slot))?;
    assert_eq!(fixture.query(), Err(RecordingDiscoveryError::Sequence));
    let fixture = Fixture::new("page-hole", RecordingQueryCodec::Avc, 3, 2)?;
    fs::remove_file(fixture.record(&fixture.catalogs[0].slot))?;
    assert_eq!(fixture.query(), Err(RecordingDiscoveryError::Sequence));
    let fixture = Fixture::new("page-overlap", RecordingQueryCodec::Avc, 3, 2)?;
    let slot = namespace_slot(fixture.request.codec, &fixture.request.scope, true, 1)?;
    fixture.publish(&slot, &fixture.catalogs[1].manifest)?;
    fs::remove_file(fixture.record(&fixture.catalogs[1].slot))?;
    assert_eq!(fixture.query(), Err(RecordingDiscoveryError::Sequence));
    Ok(())
}

#[test]
fn duplicate_window_roots_and_mismatched_page_member_bindings_refuse() -> TestResult {
    let fixture = Fixture::new("duplicate-window", RecordingQueryCodec::Avc, 3, 2)?;
    fixture.publish(&fixture.windows[2].slot, &fixture.windows[0].manifest)?;
    assert_eq!(fixture.query(), Err(RecordingDiscoveryError::Sequence));
    let mut fixture = Fixture::new("member-mismatch", RecordingQueryCodec::Avc, 3, 2)?;
    fixture.request.interval = 0..1;
    let different = avc_window(9, 31_000)?;
    fixture.publish(&fixture.windows[2].slot, different.manifest())?;
    assert_eq!(
        fixture.query(),
        Err(RecordingDiscoveryError::Catalog(
            CatalogError::WindowMismatch
        ))
    );
    Ok(())
}

#[test]
fn malformed_selected_slot_roles_and_pending_publications_never_become_gaps() -> TestResult {
    for suffix in ["-x-0000000000000000.root", "-w-bad.root"] {
        let fixture = Fixture::new("malformed-slot", RecordingQueryCodec::Avc, 3, 2)?;
        let slot = SlotName::parse(&format!(
            "{}{}",
            fixture.namespace_prefix()?,
            suffix.trim_end_matches(".root")
        ))?;
        fixture.publish(&slot, &fixture.windows[0].manifest)?;
        assert_eq!(fixture.query(), Err(RecordingDiscoveryError::Sequence));
    }
    let fixture = Fixture::new("pending", RecordingQueryCodec::Avc, 3, 2)?;
    fs::write(
        fixture
            .root
            .join("roots")
            .join(format!("{}.root.tmp", fixture.catalogs[1].slot)),
        b"pending",
    )?;
    assert_eq!(
        fixture.query(),
        Err(RecordingDiscoveryError::Storage(
            PinnedMetadataError::Audit(CustodyAuditError::PublicationInFlight),
        ))
    );
    Ok(())
}

#[test]
fn corrupt_unselected_later_catalog_or_member_prevents_an_empty_success() -> TestResult {
    for corrupt_page in [false, true] {
        let mut fixture = Fixture::new("late-corrupt", RecordingQueryCodec::Avc, 3, 2)?;
        fixture.request.interval = 0..1;
        let digest = if corrupt_page {
            fixture.catalogs[1]
                .manifest
                .metadata_digest()
                .ok_or("catalog metadata")?
        } else {
            fixture.windows[2].manifest.root()
        };
        fs::write(fixture.object(digest), b"corrupt unselected metadata")?;
        assert!(matches!(
            fixture.query(),
            Err(RecordingDiscoveryError::Storage(_))
        ));
    }
    Ok(())
}

#[test]
fn valid_inventory_growth_rebinds_the_decision_without_changing_the_selected_row() -> TestResult {
    let mut before = Fixture::new("inventory-before", RecordingQueryCodec::Avc, 3, 2)?;
    let mut after = Fixture::new("inventory-after", RecordingQueryCodec::Avc, 4, 2)?;
    before.request.interval = 1001..4599;
    after.request.interval = before.request.interval.clone();
    let first = before.query()?;
    let second = after.query()?;
    assert_eq!(first.request_digest, second.request_digest);
    assert_eq!(first.namespace_digest, second.namespace_digest);
    assert_eq!(first.rows, second.rows);
    assert_ne!(first.inventory_digest, second.inventory_digest);
    assert_ne!(first.decision_digest, second.decision_digest);
    Ok(())
}

#[test]
fn new_unindexed_window_during_page_reads_is_detected_by_final_namespace_rescan() -> TestResult {
    let fixture = Fixture::new("late-window", RecordingQueryCodec::Avc, 3, 2)?;
    let slot = namespace_slot(fixture.request.codec, &fixture.request.scope, false, 3)?;
    let later = avc_window(7, 31_000)?;
    let bytes = root_record_bytes(
        &slot,
        later.manifest().root(),
        later.manifest().children().len(),
    )?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let injected = AtomicBool::new(false);
    let failed = AtomicBool::new(false);
    let cancelled = || {
        if io.call_count(SpoolIoCall::OpenRead) >= fixture.initial_root_reads() + 3
            && !injected.swap(true, Ordering::SeqCst)
        {
            failed.store(
                fs::write(fixture.record(&slot), &bytes).is_err(),
                Ordering::SeqCst,
            );
        }
        false
    };
    let result = fixture.query_with(&io, RecordingDiscoveryLimits::default(), &cancelled);
    assert!(injected.load(Ordering::SeqCst) && !failed.load(Ordering::SeqCst));
    assert_eq!(
        result,
        Err(RecordingDiscoveryError::Storage(
            PinnedMetadataError::Changed
        ))
    );
    assert!(!fixture.object(later.manifest().root()).exists());
    assert!(io.is_read_only());
    Ok(())
}

#[test]
fn an_earlier_catalog_rebinding_during_later_reads_refuses_the_whole_observation() -> TestResult {
    let fixture = Fixture::new("late-rebind", RecordingQueryCodec::Avc, 3, 2)?;
    let catalog = &fixture.catalogs[0];
    let changed = root_record_bytes(
        &catalog.slot,
        ContentDigest::sha256(b"new earlier catalog binding"),
        catalog.manifest.children().len(),
    )?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let injected = AtomicBool::new(false);
    let failed = AtomicBool::new(false);
    let cancelled = || {
        if io.call_count(SpoolIoCall::OpenRead) >= fixture.initial_root_reads() + 7
            && !injected.swap(true, Ordering::SeqCst)
        {
            failed.store(
                fs::write(fixture.record(&catalog.slot), &changed).is_err(),
                Ordering::SeqCst,
            );
        }
        false
    };
    let result = fixture.query_with(&io, RecordingDiscoveryLimits::default(), &cancelled);
    assert!(injected.load(Ordering::SeqCst) && !failed.load(Ordering::SeqCst));
    assert_eq!(
        result,
        Err(RecordingDiscoveryError::Storage(
            PinnedMetadataError::Changed
        ))
    );
    Ok(())
}

#[test]
fn unrelated_namespace_growth_during_reads_preserves_the_selected_inventory() -> TestResult {
    let fixture = Fixture::new("unrelated-growth", RecordingQueryCodec::Avc, 3, 2)?;
    let baseline = fixture.query()?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let injected = AtomicBool::new(false);
    let failed = AtomicBool::new(false);
    let cancelled = || {
        if io.call_count(SpoolIoCall::OpenRead) >= fixture.initial_root_reads() + 3
            && !injected.swap(true, Ordering::SeqCst)
        {
            failed.store(
                fs::write(
                    fixture.root.join("roots/unrelated.root.tmp"),
                    b"unrelated pending",
                )
                .is_err(),
                Ordering::SeqCst,
            );
        }
        false
    };
    let result = fixture.query_with(&io, RecordingDiscoveryLimits::default(), &cancelled)?;
    assert!(injected.load(Ordering::SeqCst) && !failed.load(Ordering::SeqCst));
    assert_eq!(result.inventory_digest, baseline.inventory_digest);
    assert_eq!(result.decision_digest, baseline.decision_digest);
    assert_eq!(result.rows, baseline.rows);
    assert!(result.read_usage.io_calls > baseline.read_usage.io_calls);
    Ok(())
}

#[test]
fn late_deletion_of_an_unselected_earlier_source_is_checked_on_the_final_pass() -> TestResult {
    let mut fixture = Fixture::new("late-tombstone", RecordingQueryCodec::Avc, 3, 2)?;
    fixture.request.interval = 0..1;
    let leaf = *fixture.windows[0]
        .manifest
        .children()
        .iter()
        .find(|digest| !fixture.catalogs[1].manifest.children().contains(digest))
        .ok_or("earlier-only source leaf")?;
    let marker = fixture
        .root
        .join("tombstones")
        .join(format!("{}.tomb", leaf.to_text().replacen(':', "-", 1)));
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let injected = AtomicBool::new(false);
    let failed = AtomicBool::new(false);
    let cancelled = || {
        if io.call_count(SpoolIoCall::OpenRead) >= fixture.initial_root_reads() + 7
            && !injected.swap(true, Ordering::SeqCst)
        {
            failed.store(
                fs::write(&marker, b"late deletion").is_err(),
                Ordering::SeqCst,
            );
        }
        false
    };
    let result = fixture.query_with(&io, RecordingDiscoveryLimits::default(), &cancelled);
    assert!(injected.load(Ordering::SeqCst) && !failed.load(Ordering::SeqCst));
    assert_eq!(
        result,
        Err(RecordingDiscoveryError::Storage(
            PinnedMetadataError::Tombstoned
        ))
    );
    Ok(())
}

#[test]
fn discovery_scan_output_and_quote_limits_are_distinct_and_never_truncate() -> TestResult {
    let mut fixture = Fixture::new("limits", RecordingQueryCodec::Avc, 3, 2)?;
    let baseline = fixture.query()?;
    let defaults = RecordingDiscoveryLimits::default();
    for limits in [
        RecordingDiscoveryLimits {
            max_scan_roots: 4,
            ..defaults
        },
        RecordingDiscoveryLimits {
            max_windows: 2,
            max_pages: 3,
            ..defaults
        },
        RecordingDiscoveryLimits {
            max_windows: 4,
            max_pages: 1,
            ..defaults
        },
    ] {
        assert!(fixture.with_limits(limits).is_err());
    }
    let exact = RecordingDiscoveryLimits {
        max_scan_roots: 5,
        max_windows: 3,
        max_pages: 2,
        ..defaults
    };
    let bounded = fixture.with_limits(exact)?;
    assert_eq!(bounded.rows, baseline.rows);
    assert_eq!(bounded.inventory_digest, baseline.inventory_digest);
    assert_ne!(bounded.request_digest, baseline.request_digest);
    fixture.request.max_windows = 2;
    assert_eq!(fixture.query(), Err(RecordingDiscoveryError::Limit));
    fixture.request.max_windows = 3;
    fixture.request.max_hydration_bytes = baseline.quoted_hydration_bytes;
    assert_eq!(
        fixture.query()?.quoted_hydration_bytes,
        baseline.quoted_hydration_bytes
    );
    fixture.request.max_hydration_bytes -= 1;
    assert_eq!(fixture.query(), Err(RecordingDiscoveryError::Limit));
    // Even an interval with no matches must verify every window and page.
    fixture.request.interval = 0..1;
    assert!(
        fixture
            .with_limits(RecordingDiscoveryLimits {
                max_windows: 2,
                max_pages: 3,
                ..defaults
            })
            .is_err()
    );
    Ok(())
}

#[test]
fn byte_io_and_object_budgets_cover_both_namespace_scans_and_complete_metadata_revalidation()
-> TestResult {
    let fixture = Fixture::new("shared-budget", RecordingQueryCodec::Avc, 3, 2)?;
    let baseline = fixture.query()?;
    let mut exact = RecordingDiscoveryLimits::default();
    exact.metadata.max_read_bytes = baseline.read_usage.peak_reserved_read_bytes;
    exact.metadata.max_io_calls = baseline.read_usage.io_calls;
    exact.metadata.max_catalogue_entries = baseline.read_usage.pinned_roots;
    exact.metadata.max_objects = baseline.read_usage.metadata_objects;
    let bounded = fixture.with_limits(exact)?;
    assert_eq!(bounded.read_usage, baseline.read_usage);
    assert_eq!(bounded.rows, baseline.rows);
    assert_eq!(bounded.inventory_digest, baseline.inventory_digest);
    for dimension in 0..4 {
        let mut limits = exact;
        match dimension {
            0 => limits.metadata.max_read_bytes -= 1,
            1 => limits.metadata.max_io_calls -= 1,
            2 => limits.metadata.max_catalogue_entries -= 1,
            _ => limits.metadata.max_objects -= 1,
        }
        assert!(
            matches!(
                fixture.with_limits(limits),
                Err(RecordingDiscoveryError::Storage(
                    PinnedMetadataError::Audit(CustodyAuditError::Limit(_)),
                ))
            ),
            "dimension {dimension}"
        );
    }
    Ok(())
}

#[test]
fn invalid_requests_and_enlarged_limits_refuse_before_any_filesystem_access() -> TestResult {
    let fixture = Fixture::new("preflight", RecordingQueryCodec::Avc, 3, 2)?;
    for change in 0..6 {
        let mut request = fixture.request.clone();
        match change {
            0 => request.scope.recording.generation = 0,
            1 => request.scope.time_scale = 0,
            2 => request.interval = 1..1,
            3 => request.max_windows = 65,
            4 => request.max_hydration_bytes = 0,
            _ => {
                request.scope.decode_clock =
                    ContentDigest::parse(format!("sha256:{}", "0".repeat(64)))?
            }
        }
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        assert_eq!(
            discover_recordings(
                &io,
                &fixture.root,
                &request,
                RecordingDiscoveryLimits::default(),
                &|| false
            ),
            Err(RecordingDiscoveryError::InvalidRequest)
        );
        assert!(io.calls().is_empty());
    }
    for dimension in 0..4 {
        let mut limits = RecordingDiscoveryLimits::default();
        match dimension {
            0 => limits.max_scan_roots += 1,
            1 => limits.max_windows += 1,
            2 => limits.max_pages += 1,
            _ => limits.metadata.max_io_calls += 1,
        }
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        assert_eq!(
            fixture.query_with(&io, limits, &|| false),
            Err(RecordingDiscoveryError::InvalidRequest)
        );
        assert!(io.calls().is_empty());
    }
    Ok(())
}

#[test]
fn cancellation_before_or_during_discovery_has_no_successful_prefix() -> TestResult {
    let fixture = Fixture::new("cancel", RecordingQueryCodec::Avc, 3, 2)?;
    let expected = Err(RecordingDiscoveryError::Storage(
        PinnedMetadataError::Audit(CustodyAuditError::Cancelled),
    ));
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    assert_eq!(
        fixture.query_with(&io, RecordingDiscoveryLimits::default(), &|| true),
        expected
    );
    assert!(io.calls().is_empty());
    assert_eq!(
        fixture.query_with(&io, RecordingDiscoveryLimits::default(), &|| io
            .call_count(SpoolIoCall::OpenRead)
            >= fixture.initial_root_reads() + 3),
        expected
    );
    assert!(io.is_read_only());
    Ok(())
}

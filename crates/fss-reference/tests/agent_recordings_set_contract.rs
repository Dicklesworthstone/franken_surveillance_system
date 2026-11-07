#![forbid(unsafe_code)]
//! Cross-catalog discovery through real native metadata, with no original media present.

mod collector_support;
mod hevc_catalog_support;
mod hevc_recording_support;
mod recording_support;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use fss_core::{CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest};
use fss_object::{HostSpoolIo, ObjectManifest, RecordingSpoolIo, SpoolIoCall, encode_spool_object};
use fss_publication::custody_audit::CustodyAuditError;
use fss_publication::custody_audit::pinned_metadata::PinnedMetadataError;
use fss_publication::{SlotName, root_record_bytes};
use fss_reference::agent_recordings::set::{
    MAX_RECORDING_QUERY_CATALOGS, RecordingCatalogPin, RecordingSetQuery, RecordingSetQueryLimits,
    RecordingSetQueryRequest, query_recording_set,
};
use fss_reference::agent_recordings::{
    RecordingQueryCodec, RecordingQueryError, RecordingQueryLimits, RecordingQueryRequest,
    query_recordings,
};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording_catalog::hevc::{HevcCatalogWindow, prepare_hevc_catalog};
use fss_reference::rtsp::recording_catalog::{
    CatalogError, CatalogScope, CatalogWindow, prepare_catalog,
};
use fss_reference::rtsp::recording_collector::CollectorLimits;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct CatalogData {
    manifest: ObjectManifest,
    index: Vec<u8>,
}
struct Fixture {
    root: PathBuf,
    request: RecordingSetQueryRequest,
    catalogs: Vec<CatalogData>,
    windows: Vec<(SlotName, ObjectManifest)>,
    leaves: BTreeSet<ContentDigest>,
}
impl Fixture {
    fn new(name: &str, codec: RecordingQueryCodec) -> TestResult<Self> {
        let slots = [
            SlotName::parse("first-window")?,
            SlotName::parse("shared-window")?,
            SlotName::parse("last-window")?,
        ];
        let (scope, catalogs, windows, leaves, interval) = match codec {
            RecordingQueryCodec::Avc => {
                let recordings = [
                    avc_window(1, 3600)?,
                    avc_window(3, 10800)?,
                    avc_window(5, 18000)?,
                ];
                let scope = CatalogScope {
                    recording: collector_support::scope()?,
                    decode_clock: ContentDigest::sha256(b"agent-recording-set-decode-clock"),
                    time_scale: 90_000,
                };
                let mut catalogs = Vec::new();
                for pair in [[0, 1], [1, 2]] {
                    let catalog = prepare_catalog(
                        scope.clone(),
                        &pair.map(|index| CatalogWindow {
                            slot: &slots[index],
                            recording: &recordings[index],
                        }),
                    )?;
                    catalogs.push(CatalogData {
                        manifest: catalog.manifest().clone(),
                        index: catalog.index_bytes().to_vec(),
                    });
                }
                let windows = slots
                    .iter()
                    .zip(&recordings)
                    .map(|(slot, recording)| (slot.clone(), recording.manifest().clone()))
                    .collect::<Vec<_>>();
                let leaves = recordings
                    .iter()
                    .flat_map(PreparedRecording::children)
                    .map(|(_, digest, _)| digest)
                    .collect::<BTreeSet<_>>();
                (scope, catalogs, windows, leaves, 0..25200)
            }
            RecordingQueryCodec::Hevc => {
                let recordings = [
                    hevc_catalog_support::window(1000)?,
                    hevc_catalog_support::window(100_000)?,
                    hevc_catalog_support::window(200_000)?,
                ];
                let scope = hevc_catalog_support::scope()?;
                let mut catalogs = Vec::new();
                for pair in [[0, 1], [1, 2]] {
                    let catalog = prepare_hevc_catalog(
                        scope.clone(),
                        &pair.map(|index| HevcCatalogWindow {
                            slot: &slots[index],
                            recording: &recordings[index],
                        }),
                    )?;
                    catalogs.push(CatalogData {
                        manifest: catalog.manifest().clone(),
                        index: catalog.index_bytes().to_vec(),
                    });
                }
                let windows = slots
                    .iter()
                    .zip(&recordings)
                    .map(|(slot, recording)| (slot.clone(), recording.manifest().clone()))
                    .collect::<Vec<_>>();
                let leaves = recordings
                    .iter()
                    .flat_map(|recording| recording.publication_plan().children())
                    .map(|(_, digest, _)| digest)
                    .collect::<BTreeSet<_>>();
                (scope, catalogs, windows, leaves, 0..300_000)
            }
        };
        let mut root = None;
        for suffix in 0..64 {
            let candidate = std::env::temp_dir().join(format!(
                "fss-agent-recording-set-{name}-{}-{suffix}",
                std::process::id()
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
        let request = RecordingSetQueryRequest {
            codec,
            scope,
            catalogs: vec![
                RecordingCatalogPin {
                    slot: SlotName::parse("catalog-a")?,
                    root: catalogs[0].manifest.root(),
                },
                RecordingCatalogPin {
                    slot: SlotName::parse("catalog-b")?,
                    root: catalogs[1].manifest.root(),
                },
            ],
            interval,
            max_windows: 64,
            max_hydration_bytes: 256 * 1024 * 1024,
        };
        let fixture = Self {
            root,
            request,
            catalogs,
            windows,
            leaves,
        };
        for (pin, catalog) in fixture.request.catalogs.iter().zip(&fixture.catalogs) {
            fixture.put(&catalog.index)?;
            fixture.publish(&pin.slot, &catalog.manifest)?;
        }
        for (slot, manifest) in &fixture.windows {
            fixture.publish(slot, manifest)?;
        }
        Ok(fixture)
    }

    fn object(&self, digest: ContentDigest) -> PathBuf {
        self.root
            .join("spool/objects")
            .join(digest.to_text().trim_start_matches("sha256:"))
    }

    fn put(&self, bytes: &[u8]) -> TestResult {
        let digest = ContentDigest::sha256(bytes);
        fs::write(self.object(digest), encode_spool_object(digest, bytes)?)?;
        Ok(())
    }

    fn publish(&self, slot: &SlotName, manifest: &ObjectManifest) -> TestResult {
        self.put(&manifest.canonical_bytes())?;
        fs::write(
            self.root
                .join("roots")
                .join(format!("{}.root", slot.as_str())),
            root_record_bytes(slot, manifest.root(), manifest.children().len())?,
        )?;
        Ok(())
    }

    fn query(&self) -> Result<RecordingSetQuery, RecordingQueryError> {
        self.with_limits(RecordingSetQueryLimits::default())
    }

    fn with_limits(
        &self,
        limits: RecordingSetQueryLimits,
    ) -> Result<RecordingSetQuery, RecordingQueryError> {
        query_recording_set(&HostSpoolIo, &self.root, &self.request, limits, &|| false)
    }

    fn replace_catalog_index(&mut self, ordinal: usize, index: Vec<u8>) -> TestResult {
        let old = &self.catalogs[ordinal].manifest;
        let old_metadata = old.metadata_digest().ok_or("missing catalog metadata")?;
        let manifest = ObjectManifest::new(
            old.kind(),
            old.children()
                .iter()
                .copied()
                .filter(|d| *d != old_metadata),
            Some(ContentDigest::sha256(&index)),
        )?;
        self.put(&index)?;
        self.publish(&self.request.catalogs[ordinal].slot, &manifest)?;
        self.request.catalogs[ordinal].root = manifest.root();
        self.catalogs[ordinal] = CatalogData { manifest, index };
        Ok(())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
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
fn avc_and_hevc_catalog_sets_preserve_memberships_and_price_unique_windows_once() -> TestResult {
    for codec in [RecordingQueryCodec::Avc, RecordingQueryCodec::Hevc] {
        let fixture = Fixture::new(codec.as_str(), codec)?;
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let query = query_recording_set(
            &io,
            &fixture.root,
            &fixture.request,
            RecordingSetQueryLimits::default(),
            &|| false,
        )?;
        assert_eq!(query.catalogs.len(), 2);
        assert_eq!(query.scanned_windows, 4);
        assert_eq!(query.unique_windows, 3);
        assert_eq!(query.rows.len(), 3);
        assert_eq!(query.read_usage.pinned_roots, 5);
        assert_eq!(query.read_usage.metadata_objects, 7);
        assert_eq!(query.read_usage.io_calls, io.calls().len() as u64);
        for (ordinal, row) in query.rows.iter().enumerate() {
            assert_eq!(row.entry.root(), fixture.windows[ordinal].1.root());
            assert_eq!(row.entry.slot(), &fixture.windows[ordinal].0);
            assert_eq!(row.overlap, row.entry.decode_interval());
            for location in &row.locations {
                assert_eq!(
                    location.catalog_root,
                    query.catalogs[location.catalog_index].pin.root
                );
            }
        }
        let shared = &query.rows[1];
        assert_eq!(shared.locations.len(), 2);
        assert_eq!(shared.locations[0].catalog_index, 0);
        assert_eq!(shared.locations[0].ordinal, 1);
        assert_eq!(shared.locations[1].catalog_index, 1);
        assert_eq!(shared.locations[1].ordinal, 0);
        assert_eq!(
            query.quoted_hydration_bytes,
            query
                .rows
                .iter()
                .map(|r| r.entry.byte_len() as u64)
                .sum::<u64>()
        );
        let gaps = match codec {
            RecordingQueryCodec::Avc => vec![0..3600, 7200..10800, 14400..18000, 21600..25200],
            RecordingQueryCodec::Hevc => {
                vec![0..1000, 73000..100000, 172000..200000, 272000..300000]
            }
        };
        assert_eq!(query.indexed_gaps, gaps);
        assert!(io.is_read_only());
        assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
        assert_eq!(io.call_count(SpoolIoCall::NextDirEntry), 0);
        assert!(!fixture.root.join("LOCK").exists());
        for leaf in &fixture.leaves {
            assert!(query.reference_digests.contains(leaf));
            assert!(!fixture.object(*leaf).exists());
            fs::write(fixture.object(*leaf), b"corrupt source never hydrated")?;
        }
        assert_eq!(fixture.query()?, query);
    }
    Ok(())
}

#[test]
fn input_permutation_and_filesystem_path_preserve_every_decision_and_membership() -> TestResult {
    let mut first = Fixture::new("canonical-first", RecordingQueryCodec::Avc)?;
    let second = Fixture::new("canonical-second", RecordingQueryCodec::Avc)?;
    let baseline = first.query()?;
    first.request.catalogs.reverse();
    assert_eq!(first.query()?, baseline);
    assert_eq!(second.query()?, baseline);
    let mut row = baseline.rows[1].clone();
    row.locations[0].catalog_root = ContentDigest::sha256(b"different-immutable-catalog");
    assert_ne!(row.row_digest(), baseline.rows[1].row_digest());
    row = baseline.rows[1].clone();
    row.locations.pop();
    assert_ne!(row.row_digest(), baseline.rows[1].row_digest());
    Ok(())
}

#[test]
fn duplicate_or_invalid_pins_and_limits_refuse_before_any_io() -> TestResult {
    let fixture = Fixture::new("input-refusal", RecordingQueryCodec::Avc)?;
    let mut invalid = Vec::new();
    let mut request = fixture.request.clone();
    request.catalogs.clear();
    invalid.push(request);
    let mut request = fixture.request.clone();
    request.catalogs.push(request.catalogs[0].clone());
    invalid.push(request);
    let mut request = fixture.request.clone();
    request.catalogs[1].slot = request.catalogs[0].slot.clone();
    invalid.push(request);
    let mut request = fixture.request.clone();
    request.catalogs[1].root = request.catalogs[0].root;
    invalid.push(request);
    let mut request = fixture.request.clone();
    request.interval = 1..1;
    invalid.push(request);
    let mut request = fixture.request.clone();
    request.catalogs = (0..=MAX_RECORDING_QUERY_CATALOGS)
        .map(|i| {
            Ok(RecordingCatalogPin {
                slot: SlotName::parse(&format!("catalog-{i}"))?,
                root: ContentDigest::sha256(&i.to_le_bytes()),
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    invalid.push(request);
    for request in invalid {
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        assert_eq!(
            query_recording_set(
                &io,
                &fixture.root,
                &request,
                RecordingSetQueryLimits::default(),
                &|| false,
            ),
            Err(RecordingQueryError::InvalidRequest)
        );
        assert!(io.calls().is_empty());
    }
    let mut limits = RecordingSetQueryLimits::default();
    limits.max_scanned_windows += 1;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    assert_eq!(
        query_recording_set(&io, &fixture.root, &fixture.request, limits, &|| false),
        Err(RecordingQueryError::InvalidRequest)
    );
    assert!(io.calls().is_empty());
    Ok(())
}

#[test]
fn scope_codec_and_each_exact_catalog_pin_remain_mandatory() -> TestResult {
    let fixture = Fixture::new("scope", RecordingQueryCodec::Avc)?;
    let mut requests = Vec::new();
    let mut request = fixture.request.clone();
    request.codec = RecordingQueryCodec::Hevc;
    requests.push(request);
    let mut request = fixture.request.clone();
    request.scope.recording.anchor = ContentDigest::sha256(b"foreign-anchor");
    requests.push(request);
    let mut request = fixture.request.clone();
    request.scope.recording.generation += 1;
    requests.push(request);
    let mut request = fixture.request.clone();
    request.scope.decode_clock = ContentDigest::sha256(b"other-timeline");
    requests.push(request);
    let mut request = fixture.request.clone();
    request.scope.time_scale += 1;
    requests.push(request);
    let mut request = fixture.request.clone();
    request.catalogs[1].root = ContentDigest::sha256(b"wrong-second-root");
    requests.push(request);
    let mut request = fixture.request.clone();
    request.catalogs[1].slot = SlotName::parse("absent-second-catalog")?;
    requests.push(request);
    let baseline = fixture.query()?;
    for request in requests {
        assert_ne!(
            request.request_digest(RecordingSetQueryLimits::default())?,
            baseline.request_digest
        );
        assert!(
            query_recording_set(
                &HostSpoolIo,
                &fixture.root,
                &request,
                RecordingSetQueryLimits::default(),
                &|| false,
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn scan_output_and_hydration_allowances_are_aggregate_and_atomic() -> TestResult {
    let mut fixture = Fixture::new("aggregate", RecordingQueryCodec::Avc)?;
    let baseline = fixture.query()?;
    fixture.request.max_windows = 3;
    fixture.request.max_hydration_bytes = baseline.quoted_hydration_bytes;
    assert_eq!(fixture.query()?.rows, baseline.rows);
    fixture.request.max_windows = 2;
    assert_eq!(
        fixture.query(),
        Err(RecordingQueryError::Catalog(CatalogError::Limit))
    );
    fixture.request.max_windows = 3;
    fixture.request.max_hydration_bytes -= 1;
    assert_eq!(
        fixture.query(),
        Err(RecordingQueryError::Catalog(CatalogError::Limit))
    );
    fixture.request.max_hydration_bytes += 1;
    let mut limits = RecordingSetQueryLimits::default();
    limits.max_scanned_windows = 3;
    assert_eq!(
        fixture.with_limits(limits),
        Err(RecordingQueryError::Catalog(CatalogError::Limit))
    );
    // Filtering every row cannot avoid checking or charging the complete selected index universe.
    fixture.request.interval = 0..1000;
    assert_eq!(
        fixture.with_limits(limits),
        Err(RecordingQueryError::Catalog(CatalogError::Limit))
    );
    limits.max_scanned_windows = 4;
    let empty = fixture.with_limits(limits)?;
    assert!(empty.rows.is_empty());
    assert_eq!(empty.indexed_gaps, vec![0..1000]);
    assert_eq!(empty.scanned_windows, 4);
    assert_eq!(empty.unique_windows, 3);
    assert_eq!(empty.reference_digests, baseline.reference_digests);
    Ok(())
}

#[test]
fn byte_and_io_budgets_cover_all_catalogs_and_complete_final_revalidation() -> TestResult {
    let fixture = Fixture::new("metadata-budget", RecordingQueryCodec::Avc)?;
    let baseline = fixture.query()?;
    let mut limits = RecordingSetQueryLimits::default();
    limits.metadata.max_io_calls = baseline.read_usage.io_calls;
    limits.metadata.max_read_bytes = baseline.read_usage.peak_reserved_read_bytes;
    assert_eq!(fixture.with_limits(limits)?.rows, baseline.rows);
    limits.metadata.max_io_calls -= 1;
    assert_eq!(
        fixture.with_limits(limits),
        Err(RecordingQueryError::Storage(PinnedMetadataError::Audit(
            CustodyAuditError::Limit("io_calls")
        )))
    );
    limits.metadata.max_io_calls += 1;
    limits.metadata.max_read_bytes -= 1;
    assert_eq!(
        fixture.with_limits(limits),
        Err(RecordingQueryError::Storage(PinnedMetadataError::Audit(
            CustodyAuditError::Limit("read_bytes")
        )))
    );
    let mut per_catalog_calls = 0;
    for pin in &fixture.request.catalogs {
        let query = query_recordings(
            &HostSpoolIo,
            &fixture.root,
            &RecordingQueryRequest {
                codec: fixture.request.codec,
                scope: fixture.request.scope.clone(),
                catalog_slot: pin.slot.clone(),
                catalog_root: pin.root,
                interval: fixture.request.interval.clone(),
                max_windows: 64,
                max_hydration_bytes: fixture.request.max_hydration_bytes,
            },
            RecordingQueryLimits::default(),
            &|| false,
        )?;
        per_catalog_calls = per_catalog_calls.max(query.read_usage.io_calls);
    }
    assert!(per_catalog_calls < baseline.read_usage.io_calls);
    limits = RecordingSetQueryLimits::default();
    limits.metadata.max_io_calls = per_catalog_calls;
    assert_eq!(
        fixture.with_limits(limits),
        Err(RecordingQueryError::Storage(PinnedMetadataError::Audit(
            CustodyAuditError::Limit("io_calls")
        )))
    );
    Ok(())
}

#[test]
fn union_gap_math_keeps_distinct_overlaps_and_half_open_boundaries() -> TestResult {
    let mut fixture = Fixture::new("overlap", RecordingQueryCodec::Avc)?;
    // A legitimate additional recording of the same timeline overlaps two earlier windows.
    let recording = avc_window(7, 6000)?;
    let slot = SlotName::parse("overlapping-window")?;
    let catalog = prepare_catalog(
        fixture.request.scope.clone(),
        &[CatalogWindow {
            slot: &slot,
            recording: &recording,
        }],
    )?;
    let pin = RecordingCatalogPin {
        slot: SlotName::parse("catalog-c")?,
        root: catalog.manifest().root(),
    };
    fixture.put(catalog.index_bytes())?;
    fixture.publish(&pin.slot, catalog.manifest())?;
    fixture.publish(&slot, recording.manifest())?;
    fixture.request.catalogs.push(pin);
    fixture.request.interval = 5000..11000;
    let query = fixture.query()?;
    assert_eq!(query.rows.len(), 3);
    assert_eq!(query.rows[0].overlap, 5000..7200);
    assert_eq!(query.rows[1].overlap, 6000..9600);
    assert_eq!(query.rows[2].overlap, 10800..11000);
    assert_eq!(query.indexed_gaps, vec![9600..10800]);
    fixture.request.interval = 9600..10800;
    let gap = fixture.query()?;
    assert!(gap.rows.is_empty());
    assert_eq!(gap.indexed_gaps, vec![9600..10800]);
    assert_eq!(gap.quoted_hydration_bytes, 0);
    Ok(())
}

#[test]
fn a_different_slot_for_the_same_window_root_is_a_descriptor_conflict() -> TestResult {
    let mut fixture = Fixture::new("root-conflict", RecordingQueryCodec::Avc)?;
    let index = rewrite_first_descriptor(&fixture.catalogs[1].index, |descriptor| {
        descriptor.slot = "renamed-shared-window".to_owned();
    })?;
    fixture.publish(
        &SlotName::parse("renamed-shared-window")?,
        &fixture.windows[1].1,
    )?;
    fixture.replace_catalog_index(1, index)?;
    assert_eq!(
        fixture.query(),
        Err(RecordingQueryError::Catalog(CatalogError::WindowMismatch))
    );
    Ok(())
}

#[test]
fn different_roots_cannot_rebind_a_shared_window_slot_between_catalogs() -> TestResult {
    let mut fixture = Fixture::new("slot-conflict", RecordingQueryCodec::Avc)?;
    let first = avc_window(1, 3600)?;
    let last = avc_window(5, 18000)?;
    let changed = prepare_catalog(
        fixture.request.scope.clone(),
        &[
            CatalogWindow {
                slot: &fixture.windows[1].0,
                recording: &first,
            },
            CatalogWindow {
                slot: &fixture.windows[2].0,
                recording: &last,
            },
        ],
    )?;
    fixture.put(changed.index_bytes())?;
    fixture.publish(&fixture.request.catalogs[1].slot, changed.manifest())?;
    fixture.request.catalogs[1].root = changed.manifest().root();
    assert_eq!(
        fixture.query(),
        Err(RecordingQueryError::Catalog(CatalogError::WindowMismatch))
    );
    Ok(())
}

#[test]
fn rehashed_conflicting_descriptor_is_rejected_even_if_no_window_is_selected() -> TestResult {
    let mut fixture = Fixture::new("descriptor-conflict", RecordingQueryCodec::Avc)?;
    let index = rewrite_first_descriptor(&fixture.catalogs[1].index, |descriptor| {
        descriptor.numbers[0] += 1;
        descriptor.numbers[3] += 1;
    })?;
    fixture.replace_catalog_index(1, index)?;
    fixture.request.interval = 0..1000;
    assert_eq!(
        fixture.query(),
        Err(RecordingQueryError::Catalog(CatalogError::WindowMismatch))
    );
    Ok(())
}

#[test]
fn unselected_earlier_source_tombstone_arriving_during_later_catalog_read_refuses_all() -> TestResult
{
    let mut fixture = Fixture::new("late-deletion", RecordingQueryCodec::Avc)?;
    fixture.request.interval = 0..1000;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let injected = AtomicBool::new(false);
    let source = *fixture.windows[0]
        .1
        .children()
        .iter()
        .find(|digest| !fixture.catalogs[1].manifest.children().contains(digest))
        .ok_or("earlier-only referenced source child")?;
    let marker = fixture
        .root
        .join("tombstones")
        .join(format!("{}.tomb", source.to_text().replacen(':', "-", 1)));
    let cancelled = || {
        if io.call_count(SpoolIoCall::OpenRead) >= 10 && !injected.swap(true, Ordering::SeqCst) {
            return fs::write(&marker, b"late deletion of unselected earlier window").is_err();
        }
        false
    };
    let result = query_recording_set(
        &io,
        &fixture.root,
        &fixture.request,
        RecordingSetQueryLimits::default(),
        &cancelled,
    );
    assert!(injected.load(Ordering::SeqCst));
    assert_eq!(
        result,
        Err(RecordingQueryError::Storage(
            PinnedMetadataError::Tombstoned
        ))
    );
    Ok(())
}

#[test]
fn earlier_catalog_rebinding_during_later_catalog_read_is_detected_on_final_pass() -> TestResult {
    let fixture = Fixture::new("late-rebinding", RecordingQueryCodec::Avc)?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let injected = AtomicBool::new(false);
    let pin = &fixture.request.catalogs[0];
    let changed = root_record_bytes(
        &pin.slot,
        ContentDigest::sha256(b"changed-earlier-catalog"),
        fixture.catalogs[0].manifest.children().len(),
    )?;
    let record = fixture
        .root
        .join("roots")
        .join(format!("{}.root", pin.slot.as_str()));
    let cancelled = || {
        if io.call_count(SpoolIoCall::OpenRead) >= 10 && !injected.swap(true, Ordering::SeqCst) {
            return fs::write(&record, &changed).is_err();
        }
        false
    };
    let result = query_recording_set(
        &io,
        &fixture.root,
        &fixture.request,
        RecordingSetQueryLimits::default(),
        &cancelled,
    );
    assert!(injected.load(Ordering::SeqCst));
    assert_eq!(
        result,
        Err(RecordingQueryError::Storage(PinnedMetadataError::Changed))
    );
    Ok(())
}

#[test]
fn cancellation_at_start_or_after_the_second_catalog_never_returns_a_partial_result() -> TestResult
{
    let fixture = Fixture::new("cancel", RecordingQueryCodec::Avc)?;
    let expected = Err(RecordingQueryError::Storage(PinnedMetadataError::Audit(
        CustodyAuditError::Cancelled,
    )));
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    assert_eq!(
        query_recording_set(
            &io,
            &fixture.root,
            &fixture.request,
            RecordingSetQueryLimits::default(),
            &|| true,
        ),
        expected
    );
    assert!(io.calls().is_empty());
    assert_eq!(
        query_recording_set(
            &io,
            &fixture.root,
            &fixture.request,
            RecordingSetQueryLimits::default(),
            &|| io.call_count(SpoolIoCall::OpenRead) >= 10,
        ),
        expected
    );
    assert!(io.call_count(SpoolIoCall::OpenRead) >= 10);
    Ok(())
}

#[test]
fn an_unselected_missing_member_and_pending_catalog_prevent_empty_success() -> TestResult {
    let mut fixture = Fixture::new("missing-unselected", RecordingQueryCodec::Avc)?;
    fixture.request.interval = 0..1000;
    let baseline = fixture.query()?;
    for (pin, catalog) in fixture.request.catalogs.iter().zip(&fixture.catalogs) {
        assert!(baseline.reference_digests.contains(&pin.root));
        assert!(
            baseline
                .reference_digests
                .contains(&ContentDigest::sha256(&catalog.index))
        );
    }
    fs::remove_file(fixture.root.join("roots/last-window.root"))?;
    assert_eq!(
        fixture.query(),
        Err(RecordingQueryError::Storage(
            PinnedMetadataError::RootBinding
        ))
    );
    fixture.publish(&fixture.windows[2].0, &fixture.windows[2].1)?;
    fs::write(
        fixture.root.join("roots/catalog-b.root.tmp"),
        b"pending publication",
    )?;
    assert_eq!(
        fixture.query(),
        Err(RecordingQueryError::Storage(PinnedMetadataError::Audit(
            CustodyAuditError::PublicationInFlight,
        )))
    );
    Ok(())
}

struct Descriptor {
    slot: String,
    root: ContentDigest,
    numbers: [u64; 6],
    objects: [ContentDigest; 4],
}

// Construct a canonical-but-conflicting index as an adversarial producer would. Recompute
// its checksum and publication root; neither content hashing nor parsing alone detects this.
fn rewrite_first_descriptor(
    index: &[u8],
    change: impl FnOnce(&mut Descriptor),
) -> TestResult<Vec<u8>> {
    let mut decoder = CanonicalDecoder::new(&index[..index.len() - 33]);
    let mut encoder = CanonicalEncoder::new();
    encoder.text(decoder.text()?);
    encoder.u64(decoder.u64()?);
    encoder.text(decoder.text()?);
    encoder.text(decoder.text()?);
    encoder.u64(decoder.u64()?);
    for _ in 0..3 {
        encoder.digest(decoder.digest()?);
    }
    encoder.u32(decoder.u32()?);
    let count = decoder.u64()?;
    encoder.u64(count);
    let mut change = Some(change);
    for ordinal in 0..count {
        let slot = decoder.text()?.to_owned();
        let root = decoder.digest()?;
        let mut numbers = [0; 6];
        for number in &mut numbers {
            *number = decoder.u64()?;
        }
        let objects = [
            decoder.digest()?,
            decoder.digest()?,
            decoder.digest()?,
            decoder.digest()?,
        ];
        let mut descriptor = Descriptor {
            slot,
            root,
            numbers,
            objects,
        };
        if ordinal == 0 {
            if let Some(change) = change.take() {
                change(&mut descriptor);
            }
        }
        encoder.text(&descriptor.slot);
        encoder.digest(descriptor.root);
        for number in descriptor.numbers {
            encoder.u64(number);
        }
        for object in descriptor.objects {
            encoder.digest(object);
        }
    }
    decoder.ensure_finished()?;
    let mut bytes = encoder.finish();
    let digest = ContentDigest::sha256(&bytes);
    bytes.push(1);
    bytes.extend_from_slice(&digest.bytes());
    Ok(bytes)
}

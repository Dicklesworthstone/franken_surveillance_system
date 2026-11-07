#![forbid(unsafe_code)]
//! Agent native recording discovery uses real AVC/HEVC metadata and never hydrates source.

mod collector_support;
mod hevc_catalog_support;
mod hevc_recording_support;
mod recording_support;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use fss_core::{CanonicalEncode, ContentDigest};
use fss_object::{HostSpoolIo, ObjectManifest, RecordingSpoolIo, SpoolIoCall, encode_spool_object};
use fss_publication::custody_audit::CustodyAuditError;
use fss_publication::custody_audit::pinned_metadata::PinnedMetadataError;
use fss_publication::{SlotName, root_record_bytes};
use fss_reference::agent_recordings::{
    RecordingQuery, RecordingQueryCodec, RecordingQueryError, RecordingQueryLimits,
    RecordingQueryRequest, query_recordings,
};
use fss_reference::rtsp::recording::PreparedRecording;
use fss_reference::rtsp::recording_catalog::hevc::{HevcCatalogWindow, prepare_hevc_catalog};
use fss_reference::rtsp::recording_catalog::{
    CatalogError, CatalogScope, CatalogWindow, prepare_catalog,
};
use fss_reference::rtsp::recording_collector::CollectorLimits;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    root: PathBuf,
    request: RecordingQueryRequest,
    catalog: ObjectManifest,
    index: Vec<u8>,
    windows: Vec<(SlotName, ObjectManifest)>,
    leaves: BTreeSet<ContentDigest>,
}
impl Fixture {
    fn new(name: &str, codec: RecordingQueryCodec) -> TestResult<Self> {
        let first_slot = SlotName::parse("first-window")?;
        let second_slot = SlotName::parse("second-window")?;
        let (scope, catalog, index, windows, leaves, interval) = match codec {
            RecordingQueryCodec::Avc => {
                let first = avc_window(1, 3600)?;
                let second = avc_window(3, 10800)?;
                let scope = CatalogScope {
                    recording: collector_support::scope()?,
                    decode_clock: ContentDigest::sha256(b"agent-native-query-decode-clock"),
                    time_scale: 90_000,
                };
                let catalog = prepare_catalog(
                    scope.clone(),
                    &[
                        CatalogWindow {
                            slot: &first_slot,
                            recording: &first,
                        },
                        CatalogWindow {
                            slot: &second_slot,
                            recording: &second,
                        },
                    ],
                )?;
                let windows = vec![
                    (first_slot, first.manifest().clone()),
                    (second_slot, second.manifest().clone()),
                ];
                let leaves = first
                    .children()
                    .into_iter()
                    .chain(second.children())
                    .map(|(_, digest, _)| digest)
                    .collect();
                (
                    scope,
                    catalog.manifest().clone(),
                    catalog.index_bytes().to_vec(),
                    windows,
                    leaves,
                    0..18000,
                )
            }
            RecordingQueryCodec::Hevc => {
                let first = hevc_catalog_support::window(1_000)?;
                let second = hevc_catalog_support::window(100_000)?;
                let scope = hevc_catalog_support::scope()?;
                let catalog = prepare_hevc_catalog(
                    scope.clone(),
                    &[
                        HevcCatalogWindow {
                            slot: &first_slot,
                            recording: &first,
                        },
                        HevcCatalogWindow {
                            slot: &second_slot,
                            recording: &second,
                        },
                    ],
                )?;
                let windows = vec![
                    (first_slot, first.manifest().clone()),
                    (second_slot, second.manifest().clone()),
                ];
                let leaves = first
                    .publication_plan()
                    .children()
                    .into_iter()
                    .chain(second.publication_plan().children())
                    .map(|(_, digest, _)| digest)
                    .collect();
                (
                    scope,
                    catalog.manifest().clone(),
                    catalog.index_bytes().to_vec(),
                    windows,
                    leaves,
                    0..200_000,
                )
            }
        };
        let mut root = None;
        for n in 0..64 {
            let candidate = std::env::temp_dir().join(format!(
                "fss-agent-recordings-{name}-{}-{n}",
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
        let request = RecordingQueryRequest {
            codec,
            scope,
            catalog_slot: SlotName::parse("recording-catalog")?,
            catalog_root: catalog.root(),
            interval,
            max_windows: 64,
            max_hydration_bytes: 256 * 1024 * 1024,
        };
        let fixture = Self {
            root,
            request,
            catalog,
            index,
            windows,
            leaves,
        };
        fixture.put(&fixture.index)?;
        fixture.publish(&fixture.request.catalog_slot, &fixture.catalog)?;
        for (slot, window) in &fixture.windows {
            fixture.publish(slot, window)?;
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
    fn query(&self) -> Result<RecordingQuery, RecordingQueryError> {
        query_recordings(
            &HostSpoolIo,
            &self.root,
            &self.request,
            RecordingQueryLimits::default(),
            &|| false,
        )
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
fn avc_and_hevc_return_exact_handles_gaps_and_whole_window_cost_without_media() -> TestResult {
    for codec in [RecordingQueryCodec::Avc, RecordingQueryCodec::Hevc] {
        let fixture = Fixture::new(codec.as_str(), codec)?;
        let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
        let query = query_recordings(
            &io,
            &fixture.root,
            &fixture.request,
            RecordingQueryLimits::default(),
            &|| false,
        )?;
        assert_eq!(query.catalog_root, fixture.catalog.root());
        assert_eq!(
            query.catalog_metadata_digest,
            ContentDigest::sha256(&fixture.index)
        );
        assert_eq!(query.rows.len(), 2);
        assert_eq!(query.scanned_windows, 2);
        assert_eq!(query.read_usage.metadata_objects, 4);
        assert_eq!(query.read_usage.pinned_roots, 3);
        assert_eq!(
            query.quoted_hydration_bytes,
            query
                .rows
                .iter()
                .map(|r| r.entry.byte_len() as u64)
                .sum::<u64>()
        );
        for (ordinal, row) in query.rows.iter().enumerate() {
            assert_eq!(row.ordinal, ordinal);
            assert_eq!(row.entry.root(), fixture.windows[ordinal].1.root());
            assert_eq!(row.entry.slot(), &fixture.windows[ordinal].0);
            assert_eq!(row.overlap, row.entry.decode_interval());
        }
        let gaps = match codec {
            RecordingQueryCodec::Avc => vec![0..3600, 7200..10800, 14400..18000],
            RecordingQueryCodec::Hevc => vec![0..1000, 73000..100000, 172000..200000],
        };
        assert_eq!(query.indexed_gaps, gaps);
        assert!(io.is_read_only());
        assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
        assert_eq!(io.call_count(SpoolIoCall::NextDirEntry), 0);
        assert_eq!(query.read_usage.io_calls, io.calls().len() as u64);
        assert!(!fixture.root.join("LOCK").exists());
        for leaf in &fixture.leaves {
            assert!(!fixture.object(*leaf).exists());
            fs::write(
                fixture.object(*leaf),
                b"deliberately corrupt source/derivative/index envelope",
            )?;
        }
        assert_eq!(fixture.query()?, query);
    }
    Ok(())
}

#[test]
fn query_does_not_contend_with_an_active_writer_lock_or_scan_unrelated_roots() -> TestResult {
    let fixture = Fixture::new("locked", RecordingQueryCodec::Avc)?;
    let lock = fs::File::create(fixture.root.join("LOCK"))?;
    lock.try_lock()?;
    fs::write(
        fixture.root.join("roots/unrelated.root.tmp"),
        b"unrelated staged publication",
    )?;
    fs::write(
        fixture.root.join("spool/objects/unrelated"),
        b"unrelated corruption",
    )?;
    let query = fixture.query()?;
    assert_eq!(query.rows.len(), 2);
    lock.unlock()?;
    Ok(())
}

#[test]
fn exact_codec_scope_slot_and_root_pins_refuse_cross_catalog_use() -> TestResult {
    let fixture = Fixture::new("pins", RecordingQueryCodec::Avc)?;
    let mut requests = vec![];
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
    request.scope.decode_clock = ContentDigest::sha256(b"foreign-clock");
    requests.push(request);
    let mut request = fixture.request.clone();
    request.scope.time_scale += 1;
    requests.push(request);
    let mut request = fixture.request.clone();
    request.catalog_slot = SlotName::parse("missing-slot")?;
    requests.push(request);
    let mut request = fixture.request.clone();
    request.catalog_root = fixture.windows[0].1.root();
    requests.push(request);
    for request in requests {
        assert!(
            query_recordings(
                &HostSpoolIo,
                &fixture.root,
                &request,
                RecordingQueryLimits::default(),
                &|| false,
            )
            .is_err()
        );
        assert_ne!(
            request.request_digest(RecordingQueryLimits::default())?,
            fixture.query()?.request_digest
        );
    }
    Ok(())
}

#[test]
fn invalid_request_is_refused_without_any_io_and_cancellation_never_becomes_empty_success()
-> TestResult {
    let fixture = Fixture::new("invalid", RecordingQueryCodec::Avc)?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut request = fixture.request.clone();
    request.interval = 10..10;
    assert_eq!(
        query_recordings(
            &io,
            &fixture.root,
            &request,
            RecordingQueryLimits::default(),
            &|| false,
        ),
        Err(RecordingQueryError::InvalidRequest)
    );
    assert!(io.calls().is_empty());
    assert_eq!(
        query_recordings(
            &io,
            &fixture.root,
            &fixture.request,
            RecordingQueryLimits::default(),
            &|| true,
        ),
        Err(RecordingQueryError::Storage(PinnedMetadataError::Audit(
            CustodyAuditError::Cancelled
        )))
    );
    assert!(io.calls().is_empty());
    Ok(())
}

#[test]
fn even_unselected_members_must_remain_currently_published() -> TestResult {
    let mut fixture = Fixture::new("outside-filter", RecordingQueryCodec::Avc)?;
    fixture.request.interval = 0..1000;
    let empty = fixture.query()?;
    assert!(empty.rows.is_empty());
    assert_eq!(empty.indexed_gaps, vec![0..1000]);
    assert_eq!(empty.scanned_windows, 2);
    assert!(empty.reference_digests.contains(&fixture.catalog.root()));
    assert!(
        empty
            .reference_digests
            .contains(&ContentDigest::sha256(&fixture.index))
    );
    for (_, window) in &fixture.windows {
        assert!(empty.reference_digests.contains(&window.root()));
    }
    for leaf in &fixture.leaves {
        assert!(empty.reference_digests.contains(leaf));
    }
    fs::remove_file(fixture.root.join("roots/second-window.root"))?;
    assert_eq!(
        fixture.query(),
        Err(RecordingQueryError::Storage(
            PinnedMetadataError::RootBinding
        ))
    );
    Ok(())
}

#[test]
fn selected_flat_closure_tombstones_are_denied_even_when_source_is_never_read() -> TestResult {
    let mut fixture = Fixture::new("tombstone", RecordingQueryCodec::Avc)?;
    fixture.request.interval = 0..1000;
    let leaf = fixture.leaves.first().ok_or("source leaf")?;
    let marker = fixture
        .root
        .join("tombstones")
        .join(format!("{}.tomb", leaf.to_text().replacen(':', "-", 1)));
    fs::write(marker, b"malformed still denies selected closure")?;
    assert_eq!(
        fixture.query(),
        Err(RecordingQueryError::Storage(
            PinnedMetadataError::Tombstoned
        ))
    );
    Ok(())
}

#[test]
fn final_metadata_pass_detects_deletion_after_initial_catalog_verification() -> TestResult {
    let fixture = Fixture::new("late-tombstone", RecordingQueryCodec::Avc)?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let injected = AtomicBool::new(false);
    let source = *fixture.leaves.first().ok_or("source leaf")?;
    let marker = fixture
        .root
        .join("tombstones")
        .join(format!("{}.tomb", source.to_text().replacen(':', "-", 1)));
    // The catalog manifest and index have already been read before the first window manifest.
    // Inject a deletion after initial catalog child checks; the final pass must still reject it.
    let cancelled = || {
        if io.call_count(SpoolIoCall::OpenRead) >= 5 && !injected.swap(true, Ordering::SeqCst) {
            return fs::write(&marker, b"new tombstone").is_err();
        }
        false
    };
    let result = query_recordings(
        &io,
        &fixture.root,
        &fixture.request,
        RecordingQueryLimits::default(),
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
fn atomic_selection_and_nonrefilling_metadata_budgets_never_truncate_a_catalog() -> TestResult {
    let mut fixture = Fixture::new("bounded", RecordingQueryCodec::Avc)?;
    let baseline = fixture.query()?;
    fixture.request.max_windows = 1;
    assert_eq!(
        fixture.query(),
        Err(RecordingQueryError::Catalog(CatalogError::Limit))
    );
    fixture.request.max_windows = 2;
    fixture.request.max_hydration_bytes = baseline.quoted_hydration_bytes - 1;
    assert_eq!(
        fixture.query(),
        Err(RecordingQueryError::Catalog(CatalogError::Limit))
    );
    fixture.request.max_hydration_bytes += 1;
    assert_eq!(fixture.query()?.rows, baseline.rows);
    let mut limits = RecordingQueryLimits::default();
    limits.metadata.max_read_bytes = baseline.read_usage.peak_reserved_read_bytes;
    limits.metadata.max_io_calls = baseline.read_usage.io_calls;
    let exact = query_recordings(
        &HostSpoolIo,
        &fixture.root,
        &fixture.request,
        limits,
        &|| false,
    )?;
    assert_eq!(exact.rows, baseline.rows);
    assert_ne!(exact.request_digest, baseline.request_digest);
    limits.metadata.max_io_calls -= 1;
    assert_eq!(
        query_recordings(
            &HostSpoolIo,
            &fixture.root,
            &fixture.request,
            limits,
            &|| false
        ),
        Err(RecordingQueryError::Storage(PinnedMetadataError::Audit(
            CustodyAuditError::Limit("io_calls")
        )))
    );
    limits.metadata.max_io_calls += 1;
    limits.metadata.max_read_bytes -= 1;
    assert_eq!(
        query_recordings(
            &HostSpoolIo,
            &fixture.root,
            &fixture.request,
            limits,
            &|| false
        ),
        Err(RecordingQueryError::Storage(PinnedMetadataError::Audit(
            CustodyAuditError::Limit("read_bytes")
        )))
    );
    Ok(())
}

#[test]
fn half_open_gaps_and_clipped_overlaps_never_lower_the_whole_window_quote() -> TestResult {
    let mut fixture = Fixture::new("intervals", RecordingQueryCodec::Avc)?;
    let baseline = fixture.query()?;
    fixture.request.interval = 5000..11000;
    let clipped = fixture.query()?;
    assert_eq!(clipped.rows[0].overlap, 5000..7200);
    assert_eq!(clipped.rows[1].overlap, 10800..11000);
    assert_eq!(clipped.indexed_gaps, vec![7200..10800]);
    assert_eq!(
        clipped.quoted_hydration_bytes,
        baseline.quoted_hydration_bytes
    );
    assert_ne!(clipped.decision_digest, baseline.decision_digest);
    fixture.request.interval = 7200..10800;
    let gap = fixture.query()?;
    assert!(gap.rows.is_empty());
    assert_eq!(gap.indexed_gaps, vec![7200..10800]);
    assert_eq!(gap.quoted_hydration_bytes, 0);
    Ok(())
}

#[test]
fn canonical_native_verifier_rejects_a_rehashed_catalog_with_inexact_child_closure() -> TestResult {
    let mut fixture = Fixture::new("flat-closure", RecordingQueryCodec::Avc)?;
    let metadata = ContentDigest::sha256(&fixture.index);
    let missing = *fixture.leaves.first().ok_or("source leaf")?;
    let altered = ObjectManifest::new(
        fixture.catalog.kind(),
        fixture
            .catalog
            .children()
            .iter()
            .copied()
            .filter(|d| *d != missing && *d != metadata),
        Some(metadata),
    )?;
    fixture.publish(&fixture.request.catalog_slot, &altered)?;
    fixture.request.catalog_root = altered.root();
    assert_eq!(
        fixture.query(),
        Err(RecordingQueryError::Catalog(CatalogError::Digest))
    );
    Ok(())
}

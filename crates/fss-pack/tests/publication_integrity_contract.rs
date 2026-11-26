#![forbid(unsafe_code)]
//! Publication must prove current byte custody, including attached metadata, before visibility.

use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{ContentDigest, TimestampNs};
use fss_pack::{
    PACK_KIND_METADATA, PACK_KIND_RAW_PAYLOAD, PACK_RECORD_HEADER_LEN, PackConfig, PackError,
    PackObjectInput, PackStore, RootStatus, VirtualRootRecord,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Result<Self, std::io::Error> {
        let serial = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-pack-publication-integrity-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy, Debug)]
enum Publication {
    Single,
    Batch,
    Graph,
    Supersede,
}

const PUBLICATIONS: [Publication; 4] = [
    Publication::Single,
    Publication::Batch,
    Publication::Graph,
    Publication::Supersede,
];

fn root(
    id: &str,
    digest: ContentDigest,
    metadata: Option<ContentDigest>,
) -> Result<VirtualRootRecord, PackError> {
    VirtualRootRecord::new(
        id,
        digest,
        "evidence-v1",
        1,
        64,
        1,
        TimestampNs(1),
        metadata,
    )
}

fn publish(
    store: &PackStore,
    operation: Publication,
    record: VirtualRootRecord,
) -> Result<(), PackError> {
    match operation {
        Publication::Single => store.publish_root(record).map(|_| ()),
        Publication::Batch => store.publish_roots_batch(&[record]).map(|_| ()),
        Publication::Graph => store.publish_graph(&[], record).map(|_| ()),
        Publication::Supersede => store.supersede_root("previous", record).map(|_| ()),
    }
}

fn install_previous(store: &PackStore, operation: Publication) -> TestResult {
    if matches!(operation, Publication::Supersede) {
        let bytes = b"unchanged previous root";
        let _ = store.append_batch(&[PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, bytes)])?;
        let _ = store.publish_root(root("previous", ContentDigest::sha256(bytes), None)?)?;
    }
    Ok(())
}

fn assert_refused_without_catalog_change(
    store: &PackStore,
    operation: Publication,
    before_fsyncs: u64,
) -> TestResult {
    assert!(store.get_root("candidate")?.is_none(), "{operation:?}");
    assert_eq!(
        store.telemetry_snapshot()?.catalog_fsync_count,
        before_fsyncs
    );
    if matches!(operation, Publication::Supersede) {
        assert!(matches!(
            store
                .get_root("previous")?
                .ok_or("missing previous root")?
                .status,
            RootStatus::Live
        ));
    }
    Ok(())
}

#[test]
fn every_publication_refuses_missing_attached_metadata() -> TestResult {
    for operation in PUBLICATIONS {
        let dir = TestDirectory::new()?;
        let store = PackStore::open(&dir.0, PackConfig::default())?;
        install_previous(&store, operation)?;
        let bytes = b"retained source bytes";
        let _ = store.append_batch(&[PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, bytes)])?;
        let absent = ContentDigest::sha256(b"metadata not yet retained");
        let before = store.telemetry_snapshot()?.catalog_fsync_count;
        assert!(
            matches!(
                publish(
                    &store,
                    operation,
                    root("candidate", ContentDigest::sha256(bytes), Some(absent))?,
                ),
                Err(PackError::MissingObject(digest)) if digest == absent
            ),
            "{operation:?}"
        );
        assert_refused_without_catalog_change(&store, operation, before)?;
    }
    Ok(())
}

#[test]
fn every_publication_rehashes_root_and_metadata_instead_of_trusting_the_index() -> TestResult {
    for operation in PUBLICATIONS {
        for corrupt_metadata in [false, true] {
            let dir = TestDirectory::new()?;
            let store = PackStore::open(&dir.0, PackConfig::default())?;
            install_previous(&store, operation)?;
            let source = b"source bytes verified at ingest";
            let metadata = b"metadata bytes verified at ingest";
            let locations = store.append_batch(&[
                PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, source),
                PackObjectInput::new(PACK_KIND_METADATA, 0, metadata),
            ])?;
            let location = locations[usize::from(corrupt_metadata)];
            let path = store.packs_dir().join(location.pack_id.file_name());
            let mut file = OpenOptions::new().write(true).open(path)?;
            let _ = file.seek(SeekFrom::Start(
                location.offset + PACK_RECORD_HEADER_LEN as u64,
            ))?;
            file.write_all(&[0xff])?;
            file.sync_all()?;
            let before = store.telemetry_snapshot()?.catalog_fsync_count;
            assert!(
                matches!(
                    publish(
                        &store,
                        operation,
                        root(
                            "candidate",
                            ContentDigest::sha256(source),
                            Some(ContentDigest::sha256(metadata)),
                        )?,
                    ),
                    Err(PackError::CrcMismatch { .. } | PackError::DigestMismatch { .. })
                ),
                "{operation:?}, metadata={corrupt_metadata}"
            );
            assert_refused_without_catalog_change(&store, operation, before)?;
        }
    }
    Ok(())
}

#[test]
fn every_publication_refuses_tombstoned_objects_even_if_reappended() -> TestResult {
    for operation in PUBLICATIONS {
        for deleted_metadata in [false, true] {
            let dir = TestDirectory::new()?;
            let store = PackStore::open(&dir.0, PackConfig::default())?;
            install_previous(&store, operation)?;
            let source = b"source to retire";
            let metadata = b"metadata to retire";
            let source_digest = ContentDigest::sha256(source);
            let metadata_digest = ContentDigest::sha256(metadata);
            let _ = store.append_batch(&[
                PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, source),
                PackObjectInput::new(PACK_KIND_METADATA, 0, metadata),
            ])?;
            let (deleted, deleted_bytes) = if deleted_metadata {
                (metadata_digest, metadata.as_slice())
            } else {
                (source_digest, source.as_slice())
            };
            let _ = store.publish_root(root("retired", deleted, None)?)?;
            let _ =
                store.tombstone_root("retired", ContentDigest::sha256(b"explicit retirement"))?;
            assert!(store.resume_root_object_deletion("retired", deleted)?);
            // An index entry cannot overturn the permanent deletion authority.
            let _ = store.append_batch(&[PackObjectInput::new(
                PACK_KIND_RAW_PAYLOAD,
                0,
                deleted_bytes,
            )])?;
            assert!(store.lookup(&deleted)?.is_some());
            let before = store.telemetry_snapshot()?.catalog_fsync_count;
            assert!(
                matches!(
                    publish(
                        &store,
                        operation,
                        root("candidate", source_digest, Some(metadata_digest))?,
                    ),
                    Err(PackError::EvidenceDeleted { digest, .. }) if digest == deleted
                ),
                "{operation:?}, metadata={deleted_metadata}"
            );
            assert_refused_without_catalog_change(&store, operation, before)?;
        }
    }
    Ok(())
}

#[test]
fn one_bad_metadata_reference_refuses_the_entire_root_batch() -> TestResult {
    let dir = TestDirectory::new()?;
    let store = PackStore::open(&dir.0, PackConfig::default())?;
    let payload = b"shared source for batch";
    let digest = ContentDigest::sha256(payload);
    let _ = store.append_batch(&[PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, payload)])?;
    let before = store.telemetry_snapshot()?.catalog_fsync_count;
    assert!(matches!(
        store.publish_roots_batch(&[
            root("valid-first", digest, None)?,
            root(
                "invalid-second",
                digest,
                Some(ContentDigest::sha256(b"absent"))
            )?,
        ]),
        Err(PackError::MissingObject(_))
    ));
    assert_eq!(store.live_root_count()?, 0);
    assert_eq!(store.telemetry_snapshot()?.catalog_fsync_count, before);
    drop(store);
    let reopened = PackStore::open(&dir.0, PackConfig::default())?;
    assert!(reopened.list_roots(None, 10)?.entries.is_empty());
    Ok(())
}

#[test]
fn graph_failure_keeps_staged_bytes_unpublished_until_metadata_is_retained() -> TestResult {
    let dir = TestDirectory::new()?;
    let store = PackStore::open(&dir.0, PackConfig::default())?;
    let source = b"source arriving first";
    let metadata = b"later metadata closes the publication";
    let source_digest = ContentDigest::sha256(source);
    let metadata_digest = ContentDigest::sha256(metadata);
    let record = root("candidate", source_digest, Some(metadata_digest))?;
    assert!(matches!(
        store.publish_graph(
            &[PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, source)],
            record.clone(),
        ),
        Err(PackError::MissingObject(digest)) if digest == metadata_digest
    ));
    assert_eq!(store.read_verified(&source_digest)?, source);
    assert!(store.get_root("candidate")?.is_none());
    let _ = store.publish_graph(
        &[PackObjectInput::new(PACK_KIND_METADATA, 0, metadata)],
        record.clone(),
    )?;
    drop(store);
    let reopened = PackStore::open(&dir.0, PackConfig::default())?;
    assert_eq!(
        reopened
            .get_root("candidate")?
            .ok_or("missing root")?
            .record,
        record
    );
    assert_eq!(reopened.read_verified(&source_digest)?, source);
    assert_eq!(reopened.read_verified(&metadata_digest)?, metadata);
    Ok(())
}

#[test]
fn root_can_share_its_exact_bytes_with_the_metadata_role() -> TestResult {
    let dir = TestDirectory::new()?;
    let store = PackStore::open(&dir.0, PackConfig::default())?;
    let payload = b"one content identity with two explicit roles";
    let digest = ContentDigest::sha256(payload);
    let _ = store.publish_graph(
        &[PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, payload)],
        root("candidate", digest, Some(digest))?,
    )?;
    assert_eq!(store.live_root_count()?, 1);
    Ok(())
}

#[test]
fn publication_obeys_the_configured_verified_read_ceiling() -> TestResult {
    let dir = TestDirectory::new()?;
    let config = PackConfig {
        max_read_bytes: 64,
        ..PackConfig::default()
    };
    let store = PackStore::open(&dir.0, config)?;
    let source = [7_u8; 128];
    let _ = store.append_batch(&[PackObjectInput::new(PACK_KIND_RAW_PAYLOAD, 0, &source)])?;
    assert!(matches!(
        store.publish_root(root("candidate", ContentDigest::sha256(&source), None)?),
        Err(PackError::ReadLimitExceeded { .. })
    ));
    assert_eq!(store.live_root_count()?, 0);
    Ok(())
}

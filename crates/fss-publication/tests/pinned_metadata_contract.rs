#![forbid(unsafe_code)]
//! Exact-slot metadata never opens a publisher, scans a directory, or reads media leaves.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_core::{CanonicalEncode, ContentDigest};
use fss_object::{
    HostSpoolIo, ObjectManifest, RecordingSpoolIo, SpoolIoCall, encode_spool_object,
};
use fss_publication::custody_audit::pinned_metadata::{
    MetadataReadUsage, PinnedMetadataError, PinnedMetadataReader,
};
use fss_publication::custody_audit::{CustodyAuditError, CustodyAuditLimits};
use fss_publication::{SlotName, root_record_bytes};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    root: PathBuf,
    slot: SlotName,
    manifest: ObjectManifest,
    metadata: Vec<u8>,
    source: ContentDigest,
}
impl Fixture {
    fn new(name: &str) -> TestResult<Self> {
        let mut path = None;
        for n in 0..64 {
            let candidate = std::env::temp_dir().join(format!(
                "fss-pinned-metadata-{name}-{}-{n}",
                std::process::id()
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => {
                    path = Some(candidate);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        let root = path.ok_or("temporary fixture names exhausted")?;
        for directory in ["roots", "tombstones", "spool/objects"] {
            fs::create_dir_all(root.join(directory))?;
        }
        let metadata = b"small typed catalog metadata".to_vec();
        let source = ContentDigest::sha256(b"source deliberately absent from this spool");
        let manifest = ObjectManifest::new(
            "pinned-metadata-test",
            [source],
            Some(ContentDigest::sha256(&metadata)),
        )?;
        let fixture = Self {
            root,
            slot: SlotName::parse("catalog")?,
            manifest,
            metadata,
            source,
        };
        fixture.put(&fixture.manifest.canonical_bytes())?;
        fixture.put(&fixture.metadata)?;
        fixture.record(fixture.manifest.root(), fixture.manifest.children().len())?;
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
    fn record(&self, root: ContentDigest, count: usize) -> TestResult {
        fs::write(
            self.root.join("roots/catalog.root"),
            root_record_bytes(&self.slot, root, count)?,
        )?;
        Ok(())
    }
    fn tombstone(&self, digest: ContentDigest, suffix: &str) -> PathBuf {
        self.root.join("tombstones").join(format!(
            "{}.tomb{suffix}",
            digest.to_text().replacen(':', "-", 1)
        ))
    }
    fn observe(&self, limits: CustodyAuditLimits) -> Result<MetadataReadUsage, PinnedMetadataError> {
        let mut reader = PinnedMetadataReader::new(&HostSpoolIo, &self.root, limits, &|| false)?;
        let manifest = reader.manifest(&self.slot, self.manifest.root())?;
        reader.metadata(&manifest)?;
        reader.finish()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn limits() -> CustodyAuditLimits {
    CustodyAuditLimits {
        max_catalogue_entries: 2,
        max_objects: 4,
        max_edges: 4,
        max_object_bytes: 1024,
        max_read_bytes: 1024 * 1024,
        max_io_calls: 1024,
    }
}

#[test]
fn exact_metadata_reads_ignore_absent_source_and_unrelated_corruption_without_mutation() -> TestResult {
    let fixture = Fixture::new("read-only")?;
    fs::write(
        fixture.root.join("roots/unrelated.root.tmp"),
        b"unrelated in-flight writer",
    )?;
    fs::write(
        fixture.root.join("spool/objects/unrelated-garbage"),
        b"not inspected",
    )?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut reader = PinnedMetadataReader::new(&io, &fixture.root, limits(), &|| false)?;
    let manifest = reader.manifest(&fixture.slot, fixture.manifest.root())?;
    assert_eq!(reader.metadata(&manifest)?, fixture.metadata);
    let usage = reader.finish()?;
    assert_eq!(usage.metadata_objects, 2);
    assert_eq!(usage.pinned_roots, 1);
    assert_eq!(usage.reference_checks, 3);
    assert_eq!(usage.io_calls, io.calls().len() as u64);
    assert!(io.is_read_only());
    assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
    assert_eq!(io.call_count(SpoolIoCall::NextDirEntry), 0);
    assert!(!fixture.object(fixture.source).exists());
    assert!(!fixture.root.join("LOCK").exists());
    Ok(())
}

#[test]
fn arbitrary_manifests_and_wrong_root_counts_do_not_grant_metadata_reads() -> TestResult {
    let fixture = Fixture::new("authority")?;
    let mut reader = PinnedMetadataReader::new(&HostSpoolIo, &fixture.root, limits(), &|| false)?;
    assert_eq!(
        reader.metadata(&fixture.manifest),
        Err(PinnedMetadataError::MetadataInvalid)
    );
    assert_eq!(
        reader.manifest(&fixture.slot, fixture.source),
        Err(PinnedMetadataError::RootBinding)
    );
    fixture.record(fixture.manifest.root(), 0)?;
    assert_eq!(
        fixture.observe(limits()),
        Err(PinnedMetadataError::MetadataInvalid)
    );
    Ok(())
}

#[test]
fn all_deletion_marker_states_deny_metadata_even_for_unread_source_children() -> TestResult {
    let fixture = Fixture::new("deletion")?;
    for digest in [
        fixture.source,
        fixture.manifest.root(),
        ContentDigest::sha256(&fixture.metadata),
    ] {
        for suffix in ["", ".tmp", ".indeterminate"] {
            let marker = fixture.tombstone(digest, suffix);
            fs::write(
                &marker,
                b"presence denies without trusting a malformed record",
            )?;
            assert_eq!(
                fixture.observe(limits()),
                Err(PinnedMetadataError::Tombstoned)
            );
            fs::remove_file(marker)?;
        }
    }
    Ok(())
}

#[test]
fn pending_root_markers_refuse_before_admitting_the_slot() -> TestResult {
    let fixture = Fixture::new("pending-root")?;
    for suffix in ["tmp", "indeterminate"] {
        let path = fixture.root.join(format!("roots/catalog.root.{suffix}"));
        fs::write(&path, b"in-flight")?;
        assert_eq!(
            fixture.observe(limits()),
            Err(PinnedMetadataError::Audit(
                CustodyAuditError::PublicationInFlight
            ))
        );
        fs::remove_file(path)?;
    }
    Ok(())
}

#[test]
fn final_pass_refuses_changed_slots_new_tombstones_and_corrupt_metadata() -> TestResult {
    for scenario in ["root", "tombstone", "metadata"] {
        let fixture = Fixture::new(scenario)?;
        let mut reader =
            PinnedMetadataReader::new(&HostSpoolIo, &fixture.root, limits(), &|| false)?;
        let manifest = reader.manifest(&fixture.slot, fixture.manifest.root())?;
        reader.metadata(&manifest)?;
        match scenario {
            "root" => fixture.record(fixture.source, 0)?,
            "tombstone" => fs::write(fixture.tombstone(fixture.source, ""), b"denied")?,
            _ => fs::write(
                fixture.object(ContentDigest::sha256(&fixture.metadata)),
                b"damaged",
            )?,
        }
        let expected = match scenario {
            "root" => PinnedMetadataError::Changed,
            "tombstone" => PinnedMetadataError::Tombstoned,
            _ => PinnedMetadataError::MetadataUnavailable,
        };
        assert_eq!(reader.finish(), Err(expected));
    }
    Ok(())
}

#[test]
fn aggregate_byte_and_call_allowances_cover_both_passes_without_refill() -> TestResult {
    let fixture = Fixture::new("budgets")?;
    let usage = fixture.observe(limits())?;
    let exact = CustodyAuditLimits {
        max_read_bytes: usage.peak_reserved_read_bytes,
        max_io_calls: usage.io_calls,
        max_objects: 2,
        max_catalogue_entries: 1,
        max_edges: 2,
        ..limits()
    };
    assert_eq!(fixture.observe(exact)?, usage);
    for (limit, dimension) in [
        (
            CustodyAuditLimits {
                max_read_bytes: exact.max_read_bytes - 1,
                ..exact
            },
            "read_bytes",
        ),
        (
            CustodyAuditLimits {
                max_io_calls: exact.max_io_calls - 1,
                ..exact
            },
            "io_calls",
        ),
        (
            CustodyAuditLimits {
                max_objects: 1,
                ..exact
            },
            "metadata_objects",
        ),
        (
            CustodyAuditLimits {
                max_catalogue_entries: 0,
                ..exact
            },
            "pinned_roots",
        ),
        (
            CustodyAuditLimits {
                max_edges: 1,
                ..exact
            },
            "manifest_edges",
        ),
    ] {
        assert_eq!(
            fixture.observe(limit),
            Err(PinnedMetadataError::Audit(CustodyAuditError::Limit(dimension)))
        );
    }
    Ok(())
}

#[test]
fn cancellation_before_admission_during_reads_and_at_final_revalidation_returns_no_result()
-> TestResult {
    let fixture = Fixture::new("cancel")?;
    let calls = AtomicUsize::new(0);
    let count = || {
        calls.fetch_add(1, Ordering::SeqCst);
        false
    };
    let mut reader = PinnedMetadataReader::new(&HostSpoolIo, &fixture.root, limits(), &count)?;
    let manifest = reader.manifest(&fixture.slot, fixture.manifest.root())?;
    reader.metadata(&manifest)?;
    reader.finish()?;
    let total = calls.load(Ordering::SeqCst);
    for cancel_at in [0, 1, total / 4, total / 2, total - 1] {
        calls.store(0, Ordering::SeqCst);
        let cancelled = || calls.fetch_add(1, Ordering::SeqCst) >= cancel_at;
        let observation = (|| {
            let mut reader =
                PinnedMetadataReader::new(&HostSpoolIo, &fixture.root, limits(), &cancelled)?;
            let manifest = reader.manifest(&fixture.slot, fixture.manifest.root())?;
            reader.metadata(&manifest)?;
            reader.finish()
        })();
        assert_eq!(
            observation,
            Err(PinnedMetadataError::Audit(CustodyAuditError::Cancelled))
        );
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn selected_metadata_and_root_record_symlinks_are_never_deliberately_followed() -> TestResult {
    let fixture = Fixture::new("symlink")?;
    let metadata = fixture.object(ContentDigest::sha256(&fixture.metadata));
    let moved = fixture.root.join("saved-metadata");
    fs::rename(&metadata, &moved)?;
    std::os::unix::fs::symlink(&moved, &metadata)?;
    assert!(fixture.observe(limits()).is_err());
    fs::remove_file(&metadata)?;
    fs::rename(&moved, &metadata)?;
    let record = fixture.root.join("roots/catalog.root");
    let moved = fixture.root.join("saved-record");
    fs::rename(&record, &moved)?;
    std::os::unix::fs::symlink(&moved, &record)?;
    assert_eq!(
        fixture.observe(limits()),
        Err(PinnedMetadataError::RootBinding)
    );
    Ok(())
}

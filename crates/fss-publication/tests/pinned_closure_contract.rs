#![forbid(unsafe_code)]
//! Actual selected disk closures, immutable pins, deletion revalidation and cumulative quotas.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_core::{CanonicalEncode, ContentDigest};
use fss_object::{HostSpoolIo, ObjectManifest, RecordingSpoolIo, SpoolIoCall, encode_spool_object};
use fss_publication::custody_audit::pinned_closure::{
    PinnedClosureError, PinnedClosureReader, PinnedClosureUsage,
};
use fss_publication::custody_audit::pinned_metadata::PinnedMetadataError;
use fss_publication::custody_audit::{CustodyAuditError, CustodyAuditLimits};
use fss_publication::{SlotName, root_record_bytes};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
static NEXT: AtomicUsize = AtomicUsize::new(0);
fn running() -> bool {
    false
}

struct Fixture {
    root: PathBuf,
    slot: SlotName,
    manifest: ObjectManifest,
    children: Vec<Vec<u8>>,
}
impl Fixture {
    fn new() -> Test<Self> {
        let root = std::env::temp_dir().join(format!(
            "fss-pinned-closure-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&root)?;
        for path in ["roots", "tombstones", "spool/objects"] {
            fs::create_dir_all(root.join(path))?;
        }
        let children = vec![
            b"retained exact source".to_vec(),
            b"opaque derived media".to_vec(),
            b"typed metadata".to_vec(),
        ];
        let manifest = ObjectManifest::new(
            "flat_test_source_v1",
            children[..2]
                .iter()
                .map(|bytes| ContentDigest::sha256(bytes)),
            Some(ContentDigest::sha256(&children[2])),
        )?;
        let fixture = Self {
            root,
            slot: SlotName::parse("selected")?,
            manifest,
            children,
        };
        fixture.put(&fixture.manifest.canonical_bytes())?;
        for bytes in &fixture.children {
            fixture.put(bytes)?;
        }
        fixture.record(fixture.manifest.root())?;
        Ok(fixture)
    }
    fn object(&self, digest: ContentDigest) -> PathBuf {
        self.root
            .join("spool/objects")
            .join(digest.to_text().trim_start_matches("sha256:"))
    }
    fn put(&self, bytes: &[u8]) -> Test {
        let digest = ContentDigest::sha256(bytes);
        fs::write(self.object(digest), encode_spool_object(digest, bytes)?)?;
        Ok(())
    }
    fn record(&self, digest: ContentDigest) -> Test {
        fs::write(
            self.root.join("roots/selected.root"),
            root_record_bytes(&self.slot, digest, self.manifest.children().len())?,
        )?;
        Ok(())
    }
    fn read(&self, reader: &mut PinnedClosureReader<'_>) -> Test<PinnedClosureUsage> {
        let manifest = reader.manifest(&self.slot, self.manifest.root())?;
        for bytes in &self.children {
            assert_eq!(
                reader.child(&manifest, ContentDigest::sha256(bytes), 1024)?,
                *bytes
            );
        }
        Ok(reader.finish_root()?)
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
        max_objects: 8,
        max_edges: 6,
        max_object_bytes: 1024,
        max_read_bytes: 64 * 1024,
        max_io_calls: 1024,
    }
}

#[test]
fn only_selected_flat_closure_is_hydrated_without_archive_scan_or_mutation() -> Test {
    let f = Fixture::new()?;
    fs::write(
        f.root.join("roots/unrelated.root.tmp"),
        b"unrelated in-flight publication",
    )?;
    fs::write(
        f.root.join("spool/objects/unrelated-corrupt"),
        b"unrelated corruption",
    )?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut reader = PinnedClosureReader::new(&io, &f.root, limits(), &running)?;
    let observed = f.read(&mut reader)?;
    assert_eq!(observed.completed_roots, 1);
    assert_eq!(observed.objects, 4);
    assert_eq!(observed.edges, 3);
    assert_eq!(observed.reference_checks, 4);
    let final_usage = reader.finish()?;
    assert_eq!(final_usage.io_calls, io.calls().len() as u64);
    assert_eq!(io.call_count(SpoolIoCall::ReadDir), 0);
    assert_eq!(io.call_count(SpoolIoCall::NextDirEntry), 0);
    assert!(io.is_read_only());
    assert!(!f.root.join("LOCK").exists());
    Ok(())
}

#[test]
fn arbitrary_children_and_unfinished_closures_fail_closed() -> Test {
    let f = Fixture::new()?;
    let mut reader = PinnedClosureReader::new(&HostSpoolIo, &f.root, limits(), &running)?;
    let manifest = reader.manifest(&f.slot, f.manifest.root())?;
    assert_eq!(
        reader.child(&manifest, ContentDigest::sha256(b"outside"), 1024),
        Err(PinnedClosureError::Scope)
    );
    assert_eq!(reader.finish(), Err(PinnedClosureError::Stopped));
    let mut reader = PinnedClosureReader::new(&HostSpoolIo, &f.root, limits(), &running)?;
    reader.manifest(&f.slot, f.manifest.root())?;
    assert_eq!(reader.finish_root(), Err(PinnedClosureError::Incomplete));
    assert_eq!(
        reader.manifest(&f.slot, f.manifest.root()),
        Err(PinnedClosureError::Stopped)
    );
    Ok(())
}

#[test]
fn source_corruption_after_first_read_is_detected_by_final_rehash() -> Test {
    let f = Fixture::new()?;
    let mut reader = PinnedClosureReader::new(&HostSpoolIo, &f.root, limits(), &running)?;
    let manifest = reader.manifest(&f.slot, f.manifest.root())?;
    for bytes in &f.children {
        reader.child(&manifest, ContentDigest::sha256(bytes), 1024)?;
    }
    fs::write(
        f.object(ContentDigest::sha256(&f.children[0])),
        b"late corruption",
    )?;
    assert_eq!(
        reader.finish_root(),
        Err(PinnedClosureError::Observation(
            PinnedMetadataError::MetadataUnavailable
        ))
    );
    Ok(())
}

#[test]
fn exact_root_binding_is_checked_again_after_selected_payload_reads() -> Test {
    let f = Fixture::new()?;
    let mut reader = PinnedClosureReader::new(&HostSpoolIo, &f.root, limits(), &running)?;
    let manifest = reader.manifest(&f.slot, f.manifest.root())?;
    for bytes in &f.children {
        reader.child(&manifest, ContentDigest::sha256(bytes), 1024)?;
    }
    f.record(ContentDigest::sha256(b"new immutable root"))?;
    assert_eq!(
        reader.finish_root(),
        Err(PinnedClosureError::Observation(
            PinnedMetadataError::Changed
        ))
    );
    Ok(())
}

#[test]
fn all_selected_tombstone_states_deny_even_when_added_after_read() -> Test {
    let f = Fixture::new()?;
    for digest in std::iter::once(f.manifest.root()).chain(f.manifest.children().iter().copied()) {
        for suffix in ["", ".tmp", ".indeterminate"] {
            let mut reader = PinnedClosureReader::new(&HostSpoolIo, &f.root, limits(), &running)?;
            let manifest = reader.manifest(&f.slot, f.manifest.root())?;
            for bytes in &f.children {
                reader.child(&manifest, ContentDigest::sha256(bytes), 1024)?;
            }
            let path = f.root.join("tombstones").join(format!(
                "{}.tomb{suffix}",
                digest.to_text().replacen(':', "-", 1)
            ));
            fs::write(
                &path,
                b"presence denies without trusting a malformed witness",
            )?;
            assert_eq!(
                reader.finish_root(),
                Err(PinnedClosureError::Observation(
                    PinnedMetadataError::Tombstoned
                ))
            );
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

#[test]
fn root_object_edge_and_io_allowances_are_cumulative_between_completed_roots() -> Test {
    let f = Fixture::new()?;
    let mut reader = PinnedClosureReader::new(&HostSpoolIo, &f.root, limits(), &running)?;
    let first = f.read(&mut reader)?;
    let second = f.read(&mut reader)?;
    assert_eq!(second.completed_roots, 2);
    assert_eq!(second.objects, 8);
    assert_eq!(second.edges, 6);
    // Each phase repeats only its own closure, never all previously completed payloads.
    assert_eq!(second.read_bytes, first.read_bytes * 2);
    assert_eq!(second.io_calls - first.io_calls, first.io_calls - 3);
    assert!(reader.manifest(&f.slot, f.manifest.root()).is_err());
    for constrained in [
        CustodyAuditLimits {
            max_objects: 4,
            ..limits()
        },
        CustodyAuditLimits {
            max_edges: 3,
            ..limits()
        },
        CustodyAuditLimits {
            max_io_calls: first.io_calls + 1,
            ..limits()
        },
        CustodyAuditLimits {
            max_read_bytes: first.peak_reserved_read_bytes,
            ..limits()
        },
    ] {
        let mut reader = PinnedClosureReader::new(&HostSpoolIo, &f.root, constrained, &running)?;
        f.read(&mut reader)?;
        assert!(f.read(&mut reader).is_err());
    }
    Ok(())
}

#[test]
fn cancellation_before_final_revalidation_never_releases_a_complete_closure() -> Test {
    let f = Fixture::new()?;
    let stopped = AtomicBool::new(false);
    let cancelled = || stopped.load(Ordering::SeqCst);
    let mut reader = PinnedClosureReader::new(&HostSpoolIo, &f.root, limits(), &cancelled)?;
    let manifest = reader.manifest(&f.slot, f.manifest.root())?;
    for bytes in &f.children {
        reader.child(&manifest, ContentDigest::sha256(bytes), 1024)?;
    }
    stopped.store(true, Ordering::SeqCst);
    assert_eq!(
        reader.finish_root(),
        Err(PinnedClosureError::Observation(PinnedMetadataError::Audit(
            CustodyAuditError::Cancelled
        )))
    );
    assert_eq!(reader.usage().completed_roots, 0);
    Ok(())
}

#[test]
fn absent_archives_and_pending_selected_roots_are_not_recovered_or_created() -> Test {
    let f = Fixture::new()?;
    let absent = f.root.join("not-created");
    assert!(PinnedClosureReader::new(&HostSpoolIo, &absent, limits(), &running).is_err());
    assert!(!absent.exists());
    for suffix in [".tmp", ".indeterminate"] {
        let path = f.root.join(format!("roots/selected.root{suffix}"));
        fs::write(&path, b"selected uncertain publication")?;
        let mut reader = PinnedClosureReader::new(&HostSpoolIo, &f.root, limits(), &running)?;
        assert_eq!(
            reader.manifest(&f.slot, f.manifest.root()),
            Err(PinnedClosureError::Observation(PinnedMetadataError::Audit(
                CustodyAuditError::PublicationInFlight
            )))
        );
        fs::remove_file(path)?;
    }
    Ok(())
}

#[test]
fn successful_finalization_is_terminal_idempotent_and_keeps_exact_usage() -> Test {
    let f = Fixture::new()?;
    let io = RecordingSpoolIo::new(Arc::new(HostSpoolIo));
    let mut reader = PinnedClosureReader::new(&io, &f.root, limits(), &running)?;
    f.read(&mut reader)?;
    let finalized = reader.finalize()?;
    assert_eq!(finalized.io_calls, io.calls().len() as u64);
    assert_eq!(reader.finalize()?, finalized);
    assert_eq!(reader.usage(), finalized);
    assert_eq!(
        reader.manifest(&f.slot, f.manifest.root()),
        Err(PinnedClosureError::Stopped)
    );
    assert_eq!(reader.finish()?, finalized);
    assert_eq!(finalized.io_calls, io.calls().len() as u64);
    Ok(())
}

#[test]
fn late_finalize_cancellation_preserves_completed_accounting_without_claiming_success() -> Test {
    let f = Fixture::new()?;
    let stopped = AtomicBool::new(false);
    let cancelled = || stopped.load(Ordering::SeqCst);
    let mut reader = PinnedClosureReader::new(&HostSpoolIo, &f.root, limits(), &cancelled)?;
    f.read(&mut reader)?;
    stopped.store(true, Ordering::SeqCst);
    assert!(reader.finalize().is_err());
    assert_eq!(reader.usage().completed_roots, 1);
    assert_eq!(reader.finish(), Err(PinnedClosureError::Stopped));
    Ok(())
}

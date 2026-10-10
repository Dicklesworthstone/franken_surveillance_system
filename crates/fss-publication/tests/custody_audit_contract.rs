#![forbid(unsafe_code)]
//! Targeted custody audit: native envelopes and publication records, including failure paths.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use fss_core::{CanonicalEncode, ContentDigest, Generation, ObjectId, TombstoneReason, TombstoneRecord};
use fss_object::{HostSpoolIo, ObjectManifest, SpoolIo, encode_spool_object};
use fss_publication::custody_audit::{
    CustodyAuditError, CustodyAuditLimits, CustodyObjectState, LocalCustodyAudit, audit_local_roots,
};
use fss_publication::{SlotName, root_record_bytes, tombstone_record_bytes};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str) -> TestResult<Self> {
        for n in 0..32 {
            let root = std::env::temp_dir().join(format!("fss-custody-audit-{name}-{}-{n}", std::process::id()));
            match fs::create_dir(&root) {
                Ok(()) => {
                    let f = Self(root);
                    for dir in ["roots", "tombstones", "spool/objects"] { fs::create_dir_all(f.0.join(dir))?; }
                    return Ok(f);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("temporary fixture names exhausted".into())
    }
    fn object_path(&self, d: ContentDigest) -> PathBuf {
        self.0.join("spool/objects").join(d.to_text().trim_start_matches("sha256:"))
    }
    fn put(&self, bytes: &[u8]) -> TestResult<ContentDigest> {
        let d = ContentDigest::sha256(bytes);
        fs::write(self.object_path(d), encode_spool_object(d, bytes)?)?;
        Ok(d)
    }
    fn publish(&self, name: &str, children: &[ContentDigest]) -> TestResult<ContentDigest> {
        let m = ObjectManifest::new("test-custody", children.iter().copied(), None)?;
        let d = self.put(&m.canonical_bytes())?;
        self.record(name, d, m.children().len())?;
        Ok(d)
    }
    fn record(&self, name: &str, root: ContentDigest, children: usize) -> TestResult {
        fs::write(self.0.join("roots").join(format!("{name}.root")),
            root_record_bytes(&SlotName::parse(name)?, root, children)?)?;
        Ok(())
    }
    fn audit(&self, roots: &[ContentDigest]) -> TestResult<LocalCustodyAudit> {
        Ok(audit_local_roots(&HostSpoolIo, &self.0, roots, &BTreeMap::new(), limits(), &|| false)?)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
fn limits() -> CustodyAuditLimits {
    CustodyAuditLimits { max_object_bytes: 8192, ..CustodyAuditLimits::default() }
}
fn state(a: &LocalCustodyAudit, d: ContentDigest) -> TestResult<CustodyObjectState> {
    a.objects().iter().find(|o| o.digest == d).map(|o| o.state).ok_or_else(|| "object not observed".into())
}
fn inventory(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = BTreeMap::new();
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() { pending.push(entry.path()); }
            else { files.insert(entry.path(), fs::read(entry.path())?); }
        }
    }
    Ok(files)
}

#[test]
fn nested_shared_closures_are_read_once_and_unrelated_payloads_are_not_scanned() -> TestResult {
    let f = Fixture::new("shared")?;
    let leaf = f.put(b"original recording")?;
    let child = f.publish("child", &[leaf])?;
    let a = f.publish("a", &[child])?;
    let b = f.publish("b", &[leaf, child])?;
    // An unrelated damaged staged object must not make a targeted custody audit fail.
    let other = f.put(b"unrelated")?;
    fs::write(f.object_path(other), b"broken")?;
    let before = inventory(&f.0)?;
    let audit = f.audit(&[b, a])?;
    assert!(audit.all_verified());
    assert!(audit.manifest_expansion_complete());
    assert_eq!(audit.objects().len(), 4);
    assert_eq!(audit.edges(), 4);
    assert_eq!(audit, f.audit(&[a, b])?);
    assert_eq!(inventory(&f.0)?, before);
    assert_eq!(audit.objects().iter().filter(|o| o.digest == leaf).count(), 1);
    Ok(())
}

#[test]
fn manifest_shaped_opaque_objects_do_not_authorize_transitive_reads() -> TestResult {
    let f = Fixture::new("opaque")?;
    let absent = ContentDigest::sha256(b"must not be read");
    let shape = ObjectManifest::new("opaque-data", [absent], None)?;
    let opaque = f.put(&shape.canonical_bytes())?; // Deliberately no publication record.
    let root = f.publish("root", &[opaque])?;
    let audit = f.audit(&[root])?;
    assert!(audit.all_verified());
    assert_eq!(audit.objects().len(), 2);
    let row = audit.objects().iter().find(|o| o.digest == opaque).ok_or("opaque missing")?;
    assert!(!row.declared_manifest);
    assert!(row.children.is_empty());
    Ok(())
}

#[test]
fn missing_and_corrupt_leaves_stay_distinct_without_destroying_other_findings() -> TestResult {
    let f = Fixture::new("faults")?;
    let missing = f.put(b"missing")?;
    let corrupt = f.put(b"corrupt")?;
    let valid = f.put(b"valid")?;
    let root = f.publish("root", &[missing, corrupt, valid])?;
    fs::remove_file(f.object_path(missing))?;
    fs::write(f.object_path(corrupt), b"not an envelope")?;
    let audit = f.audit(&[root])?;
    assert!(!audit.all_verified());
    assert!(audit.manifest_expansion_complete());
    assert_eq!(state(&audit, missing)?, CustodyObjectState::Missing);
    assert_eq!(state(&audit, corrupt)?, CustodyObjectState::Corrupt);
    assert_eq!(state(&audit, valid)?, CustodyObjectState::Verified);
    Ok(())
}

#[test]
fn an_unreadable_manifest_is_not_relabelled_as_an_opaque_verified_leaf() -> TestResult {
    let f = Fixture::new("branch")?;
    let hidden = f.put(b"hidden child")?;
    let manifest = f.publish("child", &[hidden])?;
    let root = f.publish("root", &[manifest])?;
    fs::remove_file(f.object_path(manifest))?;
    let audit = f.audit(&[root])?;
    assert!(!audit.all_verified());
    assert!(!audit.manifest_expansion_complete());
    assert_eq!(state(&audit, manifest)?, CustodyObjectState::Missing);
    assert!(audit.objects().iter().all(|o| o.digest != hidden));
    Ok(())
}

#[test]
fn deletion_authority_dominates_existing_bytes_and_stops_manifest_expansion() -> TestResult {
    let f = Fixture::new("deleted")?;
    let leaf = f.put(b"secret source")?;
    let child = f.publish("child", &[leaf])?;
    let root = f.publish("root", &[child])?;
    // If a denied object were opened, its corruption would be visible instead of Deleted.
    fs::write(f.object_path(child), b"still present after a partial deletion")?;
    let proof = ContentDigest::sha256(b"verified deletion plan supplied by caller");
    let denied = BTreeMap::from([(child, proof)]);
    let audit = audit_local_roots(&HostSpoolIo, &f.0, &[root], &denied, limits(), &|| false)?;
    assert_eq!(state(&audit, child)?, CustodyObjectState::Deleted);
    assert!(!audit.manifest_expansion_complete());
    assert_eq!(audit.objects().len(), 2);
    let row = audit.objects().iter().find(|o| o.digest == child).ok_or("denied missing")?;
    assert_eq!(row.denial_digest, Some(proof));
    assert_eq!(row.verified_payload_bytes, None);
    Ok(())
}

#[test]
fn local_tombstones_also_deny_bytes_without_an_upstream_deletion_index() -> TestResult {
    let f = Fixture::new("tombstone")?;
    let leaf = f.put(b"erased logically, still stored")?;
    let root = f.publish("root", &[leaf])?;
    let tombstone = TombstoneRecord::new(
        ObjectId::parse("object:source:1")?, Generation(2), Generation(1),
        TombstoneReason::Deleted, Some(leaf), ContentDigest::sha256(b"privacy policy"),
    )?;
    fs::write(f.0.join("tombstones").join(format!("{}.tomb", leaf.to_text().replacen(':', "-", 1))),
        tombstone_record_bytes(&tombstone)?)?;
    let audit = f.audit(&[root])?;
    assert_eq!(state(&audit, leaf)?, CustodyObjectState::LocallyTombstoned);
    assert!(!audit.all_verified());
    Ok(())
}

#[test]
fn invalid_manifest_bytes_and_disagreeing_child_counts_are_typed_faults() -> TestResult {
    let f = Fixture::new("bad-manifest")?;
    let not_manifest = f.put(b"valid object but not a manifest")?;
    f.record("a", not_manifest, 0)?;
    let valid = f.publish("b", &[])?;
    f.record("b", valid, 1)?;
    let audit = f.audit(&[valid, not_manifest])?;
    assert_eq!(state(&audit, valid)?, CustodyObjectState::InvalidManifest);
    assert_eq!(state(&audit, not_manifest)?, CustodyObjectState::InvalidManifest);
    assert!(!audit.manifest_expansion_complete());
    Ok(())
}

#[test]
fn truncated_foreign_and_pending_catalogues_never_produce_closure_success() -> TestResult {
    for (name, filename, content, expected) in [
        ("bad-record", "root.root", b"broken".as_slice(), CustodyAuditError::CatalogueInvalid),
        ("foreign", "unknown", b"foreign".as_slice(), CustodyAuditError::CatalogueInvalid),
        ("pending", "new.root.tmp", b"pending".as_slice(), CustodyAuditError::PublicationInFlight),
        ("uncertain", "new.root.indeterminate", b"pending".as_slice(), CustodyAuditError::PublicationInFlight),
    ] {
        let f = Fixture::new(name)?;
        let root = f.publish("root", &[])?;
        fs::write(f.0.join("roots").join(filename), content)?;
        assert_eq!(audit_local_roots(&HostSpoolIo, &f.0, &[root], &BTreeMap::new(), limits(), &|| false), Err(expected));
    }
    Ok(())
}

#[test]
fn staged_unpublished_duplicate_empty_and_invalid_scopes_are_refused() -> TestResult {
    let f = Fixture::new("scope")?;
    let m = ObjectManifest::new("staged-only", [], None)?;
    let staged = f.put(&m.canonical_bytes())?;
    assert_eq!(audit_local_roots(&HostSpoolIo, &f.0, &[staged], &BTreeMap::new(), limits(), &|| false), Err(CustodyAuditError::RootNotPublished));
    for roots in [vec![], vec![staged, staged], vec![ContentDigest::parse(format!("sha256:{}", "0".repeat(64)))?]] {
        assert_eq!(audit_local_roots(&HostSpoolIo, &f.0, &roots, &BTreeMap::new(), limits(), &|| false), Err(CustodyAuditError::InvalidRequest));
    }
    Ok(())
}

#[test]
fn every_aggregate_allowance_is_nonrefillable_and_exact_boundaries_are_usable() -> TestResult {
    let f = Fixture::new("budgets")?;
    let leaf = f.put(b"source")?;
    let child = f.publish("child", &[leaf])?;
    let root = f.publish("root", &[leaf, child])?;
    let baseline = f.audit(&[root])?;
    let exact = CustodyAuditLimits {
        max_catalogue_entries: 2, max_objects: 3, max_edges: 3,
        max_read_bytes: baseline.peak_reserved_read_bytes(), max_io_calls: baseline.io_calls(), ..limits()
    };
    assert!(audit_local_roots(&HostSpoolIo, &f.0, &[root], &BTreeMap::new(), exact, &|| false)?.all_verified());
    for (limited, expected) in [
        (CustodyAuditLimits { max_catalogue_entries: 1, ..exact }, "catalogue_entries"),
        (CustodyAuditLimits { max_objects: 2, ..exact }, "objects"),
        (CustodyAuditLimits { max_edges: 2, ..exact }, "edges"),
        (CustodyAuditLimits { max_read_bytes: exact.max_read_bytes - 1, ..exact }, "read_bytes"),
        (CustodyAuditLimits { max_io_calls: exact.max_io_calls - 1, ..exact }, "io_calls"),
    ] {
        assert_eq!(audit_local_roots(&HostSpoolIo, &f.0, &[root], &BTreeMap::new(), limited, &|| false), Err(CustodyAuditError::Limit(expected)));
    }
    Ok(())
}

#[test]
fn per_object_size_refusal_is_not_misreported_as_corruption() -> TestResult {
    let f = Fixture::new("object-bound")?;
    let large = f.put(&vec![7; 4096])?;
    let root = f.publish("root", &[large])?;
    let audit = audit_local_roots(&HostSpoolIo, &f.0, &[root], &BTreeMap::new(), CustodyAuditLimits { max_object_bytes: 1024, ..limits() }, &|| false)?;
    assert_eq!(state(&audit, large)?, CustodyObjectState::ObjectOverLimit);
    assert!(!audit.all_verified());
    Ok(())
}

#[test]
fn cancellation_never_becomes_a_corruption_or_success_report() -> TestResult {
    let f = Fixture::new("cancel")?;
    let root = f.publish("root", &[])?;
    assert_eq!(audit_local_roots(&HostSpoolIo, &f.0, &[root], &BTreeMap::new(), limits(), &|| true), Err(CustodyAuditError::Cancelled));
    for stop in 1..80 {
        let checks = std::sync::atomic::AtomicUsize::new(0);
        let result = audit_local_roots(&HostSpoolIo, &f.0, &[root], &BTreeMap::new(), limits(), &|| {
            checks.fetch_add(1, Ordering::SeqCst) >= stop
        });
        match result { Err(e) => assert_eq!(e, CustodyAuditError::Cancelled), Ok(a) => assert!(a.all_verified()) }
    }
    Ok(())
}

#[test]
fn aliases_with_inconsistent_counts_are_not_arbitrarily_selected() -> TestResult {
    let f = Fixture::new("aliases")?;
    let root = f.publish("root", &[])?;
    f.record("alias", root, 1)?;
    assert_eq!(audit_local_roots(&HostSpoolIo, &f.0, &[root], &BTreeMap::new(), limits(), &|| false), Err(CustodyAuditError::CatalogueInvalid));
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlinked_catalogues_are_refused_and_symlinked_payloads_are_not_served() -> TestResult {
    let f = Fixture::new("symlink")?;
    let leaf = f.put(b"private bytes")?;
    let root = f.publish("root", &[leaf])?;
    fs::remove_file(f.object_path(leaf))?;
    std::os::unix::fs::symlink(f.0.join("roots/root.root"), f.object_path(leaf))?;
    assert_eq!(state(&f.audit(&[root])?, leaf)?, CustodyObjectState::Corrupt);
    fs::rename(f.0.join("roots/root.root"), f.0.join("original-record"))?;
    std::os::unix::fs::symlink(f.0.join("original-record"), f.0.join("roots/root.root"))?;
    assert_eq!(audit_local_roots(&HostSpoolIo, &f.0, &[root], &BTreeMap::new(), limits(), &|| false), Err(CustodyAuditError::CatalogueInvalid));
    Ok(())
}

// Fault injection at a real payload read, after the first catalogue was already observed.
#[derive(Debug)]
struct ChangeOnRead { watched: PathBuf, record: PathBuf, replacement: Vec<u8>, armed: AtomicBool }
macro_rules! delegate {
    ($name:ident($($arg:ident: $ty:ty),*) -> $result:ty) => {
        fn $name(&self, $($arg: $ty),*) -> $result { HostSpoolIo.$name($($arg),*) }
    };
}
impl SpoolIo for ChangeOnRead {
    delegate!(create_dir_all(p: &Path) -> std::io::Result<()>);
    delegate!(metadata(p: &Path) -> std::io::Result<fs::Metadata>);
    delegate!(symlink_metadata(p: &Path) -> std::io::Result<fs::Metadata>);
    delegate!(open_lock(p: &Path) -> std::io::Result<fs::File>);
    delegate!(try_lock(f: &fs::File) -> Result<(), fs::TryLockError>);
    delegate!(try_lock_shared(f: &fs::File) -> Result<(), fs::TryLockError>);
    delegate!(create_dir(p: &Path) -> std::io::Result<()>);
    delegate!(read_dir(p: &Path) -> std::io::Result<fs::ReadDir>);
    delegate!(next_dir_entry(e: &mut fs::ReadDir) -> Option<std::io::Result<fs::DirEntry>>);
    delegate!(entry_file_type(e: &fs::DirEntry) -> std::io::Result<fs::FileType>);
    delegate!(create_new(p: &Path) -> std::io::Result<fs::File>);
    delegate!(write(f: &mut fs::File, b: &[u8]) -> std::io::Result<usize>);
    delegate!(sync_file(f: &fs::File) -> std::io::Result<()>);
    fn open_read(&self, path: &Path) -> std::io::Result<fs::File> {
        if path == self.watched && self.armed.swap(false, Ordering::SeqCst) { fs::write(&self.record, &self.replacement)?; }
        HostSpoolIo.open_read(path)
    }
    delegate!(read_bounded(f: &mut fs::File, n: u64) -> std::io::Result<Vec<u8>>);
    delegate!(rename(a: &Path, b: &Path) -> std::io::Result<()>);
    delegate!(remove_file(p: &Path) -> std::io::Result<()>);
    delegate!(sync_directory(p: &Path) -> std::io::Result<()>);
    delegate!(hard_link(a: &Path, b: &Path) -> std::io::Result<()>);
}
#[test]
fn publication_change_during_a_payload_read_invalidates_the_entire_audit() -> TestResult {
    let f = Fixture::new("change")?;
    let leaf = f.put(b"source")?;
    let root = f.publish("root", &[leaf])?;
    let io = ChangeOnRead {
        watched: f.object_path(root), record: f.0.join("roots/root.root"),
        replacement: root_record_bytes(&SlotName::parse("root")?, ContentDigest::sha256(b"different root"), 0)?,
        armed: AtomicBool::new(true),
    };
    assert_eq!(audit_local_roots(&io, &f.0, &[root], &BTreeMap::new(), limits(), &|| false), Err(CustodyAuditError::CatalogueChanged));
    Ok(())
}

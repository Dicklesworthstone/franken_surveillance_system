#![forbid(unsafe_code)]
//! Authority-selected manifests need no local slot; slot-only admission stays unchanged.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use fss_core::{CanonicalEncode, ContentDigest};
use fss_object::{HostSpoolIo, ObjectManifest, encode_spool_object};
use fss_publication::custody_audit::{
    CustodyAuditError, CustodyAuditLimits, CustodyObjectState, CustodyRootBasis,
    LocalCustodyAudit, audit_authority_roots, audit_local_roots,
};
use fss_publication::{SlotName, root_record_bytes};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..32 {
            let root = std::env::temp_dir().join(format!(
                "fss-authority-custody-{name}-{}-{attempt}", std::process::id(),
            ));
            match fs::create_dir(&root) {
                Ok(()) => {
                    let fixture = Self(root);
                    for dir in ["roots", "tombstones", "spool/objects"] {
                        fs::create_dir_all(fixture.0.join(dir))?;
                    }
                    return Ok(fixture);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("temporary names exhausted".into())
    }
    fn path(&self, digest: ContentDigest) -> PathBuf {
        self.0.join("spool/objects").join(digest.to_text().trim_start_matches("sha256:"))
    }
    fn put(&self, bytes: &[u8]) -> TestResult<ContentDigest> {
        let digest = ContentDigest::sha256(bytes);
        fs::write(self.path(digest), encode_spool_object(digest, bytes)?)?;
        Ok(digest)
    }
    fn manifest(&self, kind: &str, children: &[ContentDigest]) -> TestResult<ContentDigest> {
        self.put(&ObjectManifest::new(kind, children.iter().copied(), None)?.canonical_bytes())
    }
    fn record(&self, name: &str, digest: ContentDigest, count: usize) -> TestResult {
        fs::write(self.0.join("roots").join(format!("{name}.root")),
            root_record_bytes(&SlotName::parse(name)?, digest, count)?)?;
        Ok(())
    }
    fn audit(&self, roots: &[ContentDigest]) -> TestResult<LocalCustodyAudit> {
        Ok(audit_authority_roots(&HostSpoolIo, &self.0, roots, &BTreeMap::new(), limits(), &|| false)?)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
fn limits() -> CustodyAuditLimits {
    CustodyAuditLimits { max_object_bytes: 8192, ..CustodyAuditLimits::default() }
}
fn state(audit: &LocalCustodyAudit, digest: ContentDigest) -> TestResult<CustodyObjectState> {
    audit.objects().iter().find(|row| row.digest == digest)
        .map(|row| row.state).ok_or_else(|| "object not observed".into())
}

#[test]
fn ledger_selected_root_expands_without_fabricating_a_slot() -> TestResult {
    let f = Fixture::new("no-slot")?;
    let source = f.put(b"retained source")?;
    let provenance = f.manifest("retained-provenance", &[source])?;
    f.record("provenance", provenance, 1)?;
    let event = f.manifest("event-revision", &[provenance])?;
    assert_eq!(audit_local_roots(&HostSpoolIo, &f.0, &[event], &BTreeMap::new(), limits(), &|| false),
        Err(CustodyAuditError::RootNotPublished));
    let audit = f.audit(&[event])?;
    assert!(audit.all_verified());
    assert!(audit.manifest_expansion_complete());
    assert_eq!(audit.root_basis(), CustodyRootBasis::CallerVerifiedAuthority);
    assert_eq!(audit.publication_records(), 1);
    assert_eq!(audit.objects().len(), 3);
    assert_eq!(audit.edges(), 2);
    assert_eq!(state(&audit, source)?, CustodyObjectState::Verified);
    assert_eq!(fs::read_dir(f.0.join("roots"))?.count(), 1);
    let local = audit_local_roots(&HostSpoolIo, &f.0, &[provenance], &BTreeMap::new(), limits(), &|| false)?;
    assert_eq!(local.root_basis(), CustodyRootBasis::LocalPublicationRecords);
    Ok(())
}

#[test]
fn authority_scope_does_not_recursively_promote_manifest_shaped_leaves() -> TestResult {
    let f = Fixture::new("opaque")?;
    let absent = ContentDigest::sha256(b"not authorized for expansion");
    let opaque = f.manifest("opaque-bytes", &[absent])?;
    let event = f.manifest("event-revision", &[opaque])?;
    let audit = f.audit(&[event])?;
    assert!(audit.all_verified());
    assert_eq!(audit.objects().len(), 2);
    assert!(!audit.objects().iter().find(|row| row.digest == opaque).ok_or("opaque missing")?.declared_manifest);
    // A second independently selected authority root supplies the otherwise missing role.
    let expanded = f.audit(&[event, opaque])?;
    assert_eq!(state(&expanded, absent)?, CustodyObjectState::Missing);
    assert!(!expanded.all_verified());
    Ok(())
}

#[test]
fn absent_corrupt_and_non_manifest_authority_roots_never_look_intact() -> TestResult {
    let f = Fixture::new("root-faults")?;
    let missing = ContentDigest::sha256(b"missing manifest");
    let corrupt = f.manifest("corrupt-root", &[])?;
    fs::write(f.path(corrupt), b"damaged envelope")?;
    let opaque = f.put(b"validly hashed, not a manifest")?;
    let audit = f.audit(&[opaque, corrupt, missing])?;
    assert_eq!(state(&audit, missing)?, CustodyObjectState::Missing);
    assert_eq!(state(&audit, corrupt)?, CustodyObjectState::Corrupt);
    assert_eq!(state(&audit, opaque)?, CustodyObjectState::InvalidManifest);
    assert!(audit.objects().iter().all(|row| row.declared_manifest));
    assert!(!audit.manifest_expansion_complete());
    Ok(())
}

#[test]
fn deletion_denies_an_authority_root_before_any_payload_read() -> TestResult {
    let f = Fixture::new("denied-root")?;
    let source = f.put(b"private source")?;
    let root = f.manifest("event-revision", &[source])?;
    fs::write(f.path(root), b"bytes still present after deletion")?;
    let proof = ContentDigest::sha256(b"verified committed denial");
    let audit = audit_authority_roots(&HostSpoolIo, &f.0, &[root],
        &BTreeMap::from([(root, proof)]), limits(), &|| false)?;
    assert_eq!(state(&audit, root)?, CustodyObjectState::Deleted);
    assert_eq!(audit.objects().len(), 1);
    assert_eq!(audit.objects()[0].denial_digest, Some(proof));
    assert_eq!(audit.objects()[0].verified_payload_bytes, None);
    // Empty metadata directories and a denied root require no file-payload reads at all.
    assert_eq!(audit.charged_read_bytes(), 0);
    assert!(!audit.manifest_expansion_complete());
    Ok(())
}

#[test]
fn authority_selection_does_not_override_local_metadata_or_child_counts() -> TestResult {
    let f = Fixture::new("conflict")?;
    let root = f.manifest("event-revision", &[])?;
    f.record("conflicting-count", root, 1)?;
    assert_eq!(state(&f.audit(&[root])?, root)?, CustodyObjectState::InvalidManifest);
    fs::write(f.0.join("roots/pending.root.tmp"), b"pending")?;
    assert_eq!(audit_authority_roots(&HostSpoolIo, &f.0, &[root], &BTreeMap::new(), limits(), &|| false),
        Err(CustodyAuditError::PublicationInFlight));
    Ok(())
}

#[test]
fn shared_authority_roots_use_one_meter_and_refuse_underfunded_complete_walks() -> TestResult {
    let f = Fixture::new("aggregate")?;
    let leaf = f.put(b"shared source")?;
    let a = f.manifest("event-a", &[leaf])?;
    let b = f.manifest("event-b", &[leaf, a])?;
    let baseline = f.audit(&[b, a])?;
    assert_eq!(baseline, f.audit(&[a, b])?);
    assert_eq!(baseline.objects().len(), 3);
    assert_eq!(baseline.edges(), 3);
    let exact = CustodyAuditLimits {
        max_objects: 3, max_edges: 3, max_catalogue_entries: 0,
        max_read_bytes: baseline.peak_reserved_read_bytes(), max_io_calls: baseline.io_calls(),
        ..limits()
    };
    assert_eq!(baseline, audit_authority_roots(&HostSpoolIo, &f.0, &[a, b], &BTreeMap::new(), exact, &|| false)?);
    for small in [
        CustodyAuditLimits { max_objects: 2, ..exact },
        CustodyAuditLimits { max_edges: 2, ..exact },
        CustodyAuditLimits { max_read_bytes: exact.max_read_bytes - 1, ..exact },
        CustodyAuditLimits { max_io_calls: exact.max_io_calls - 1, ..exact },
    ] {
        assert!(matches!(audit_authority_roots(&HostSpoolIo, &f.0, &[a, b], &BTreeMap::new(), small, &|| false),
            Err(CustodyAuditError::Limit(_))));
    }
    assert_eq!(audit_authority_roots(&HostSpoolIo, &f.0, &[a], &BTreeMap::new(), limits(), &|| true),
        Err(CustodyAuditError::Cancelled));
    for roots in [vec![], vec![a, a]] {
        assert_eq!(audit_authority_roots(&HostSpoolIo, &f.0, &roots, &BTreeMap::new(), limits(), &|| false),
            Err(CustodyAuditError::InvalidRequest));
    }
    Ok(())
}

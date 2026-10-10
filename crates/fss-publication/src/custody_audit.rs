#![forbid(unsafe_code)]
//! Targeted read-only custody checks over the explicitly published manifest universe.
//!
//! Unlike whole-spool inspection, this reads payloads only in the selected roots' closure.
//! A manifest role comes from a valid local root record or an explicitly selected manifest
//! root whose authority the caller verified. Manifest-shaped opaque bytes are never followed.
//! No locks, holds, repairs, media decode or writes occur.
//! Root/tombstone catalogues are compared before and after the walk. This detects observed
//! publication changes, not an atomic filesystem snapshot or a guarantee of future availability.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, ContentDigest, DigestAlgorithm,
    TombstoneRecord,
};
use fss_object::{CorruptionKind, ObjectManifest, SpoolError, SpoolIo};

use crate::{
    LOCAL_ROOT_RECORD_DOMAIN, LOCAL_ROOT_RECORD_FORMAT_VERSION, LOCAL_ROOTS_DIR,
    LOCAL_TOMBSTONE_RECORD_DOMAIN, LOCAL_TOMBSTONES_DIR, LocalPublicationError,
    MAX_ROOT_RECORD_BYTES, MAX_TOMBSTONE_RECORD_BYTES, ROOT_RECORD_SUFFIX, SlotName,
    TOMBSTONE_RECORD_SUFFIX, read_verified_with_io, root_record_bytes, tombstone_record_bytes,
};

mod io;
use io::AuditIo;

/// Maximum selected root digests.
pub const MAX_AUDIT_ROOTS: usize = 128;
/// Maximum entries per publication metadata directory, including foreign/pending entries.
pub const MAX_AUDIT_CATALOGUE_ENTRIES: usize = 65_536;
/// Maximum unique reachable objects, including manifest bodies.
pub const MAX_AUDIT_OBJECTS: usize = 65_536;
/// Maximum manifest edges inspected, including edges to already visited shared objects.
pub const MAX_AUDIT_EDGES: usize = 262_144;
/// Hard ceiling for aggregate charged file-read bytes across BOTH catalogue reads and payloads.
pub const MAX_AUDIT_READ_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Hard ceiling on filesystem calls, including directory iteration and metadata calls.
pub const MAX_AUDIT_IO_CALLS: u64 = 4_000_000;

/// Aggregate, nonrefillable allowances. Zero is allowed and refuses the first corresponding work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustodyAuditLimits {
    /// Entries admitted from each metadata directory on each of two passes.
    pub max_catalogue_entries: usize,
    /// Unique objects in the selected union closure.
    pub max_objects: usize,
    /// All inspected manifest edges, not just newly discovered children.
    pub max_edges: usize,
    /// Payload ceiling passed to the existing spool decoder.
    pub max_object_bytes: usize,
    /// All file reads, including headers, probes and both metadata passes.
    pub max_read_bytes: u64,
    /// All filesystem calls through the supplied I/O capability.
    pub max_io_calls: u64,
}

impl Default for CustodyAuditLimits {
    fn default() -> Self {
        Self {
            max_catalogue_entries: 8192,
            max_objects: 16_384,
            max_edges: 65_536,
            max_object_bytes: 16 * 1024 * 1024,
            max_read_bytes: 512 * 1024 * 1024,
            max_io_calls: 1_000_000,
        }
    }
}

impl CustodyAuditLimits {
    fn validate(self) -> Result<(), CustodyAuditError> {
        if self.max_catalogue_entries > MAX_AUDIT_CATALOGUE_ENTRIES
            || self.max_objects > MAX_AUDIT_OBJECTS
            || self.max_edges > MAX_AUDIT_EDGES
            || self.max_object_bytes > fss_object::MAX_OBJECT_BYTES
            || self.max_read_bytes > MAX_AUDIT_READ_BYTES
            || self.max_io_calls > MAX_AUDIT_IO_CALLS
        {
            return Err(CustodyAuditError::InvalidRequest);
        }
        Ok(())
    }
}

/// Why no complete audit report can be returned. Errors never return an intact-closure claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CustodyAuditError {
    /// Empty, duplicate, non-SHA-256 or oversized scope, or limits above the hard ceilings.
    InvalidRequest,
    /// An aggregate resource dimension was exhausted. No implicit smaller scope or retry.
    Limit(&'static str),
    /// Caller cancellation; checked at every filesystem call and graph expansion.
    Cancelled,
    /// A missing, foreign, symlinked, malformed or inconsistent publication catalogue.
    CatalogueInvalid,
    /// Pending root records make publication state uncertain.
    PublicationInFlight,
    /// A selected root has no explicit, validated publication record.
    RootNotPublished,
    /// Publication or local tombstone metadata changed during the observation.
    CatalogueChanged,
    /// The I/O capability violated its bounded-read contract or attempted a mutation.
    IoContract,
}

impl CustodyAuditError {
    /// Stable reason within the existing operator runtime error family.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_custody_audit_request",
            Self::Limit(_) => "custody_audit_budget_exhausted",
            Self::Cancelled => "custody_audit_cancelled",
            Self::CatalogueInvalid => "publication_catalogue_unverifiable",
            Self::PublicationInFlight => "publication_in_flight",
            Self::RootNotPublished => "selected_root_not_published",
            Self::CatalogueChanged => "publication_catalogue_changed",
            Self::IoContract => "custody_io_contract_violated",
        }
    }
}
impl fmt::Display for CustodyAuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit(dimension) => write!(f, "{}: {dimension}", self.reason()),
            _ => f.write_str(self.reason()),
        }
    }
}
impl std::error::Error for CustodyAuditError {}

/// Byte availability of one exact object, not its physical truth or evidential strength.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyObjectState {
    /// Exact payload and, when declared, canonical manifest and child-count checks succeeded.
    Verified,
    /// A verified upstream deletion plan denies this digest, even if bytes still exist.
    Deleted,
    /// The local publication owner has a canonical tombstone for this digest.
    LocallyTombstoned,
    /// The expected object file is absent.
    Missing,
    /// Envelope or payload integrity failed; no untrusted bytes were traversed.
    Corrupt,
    /// Validly hashed bytes fail their explicitly published manifest contract.
    InvalidManifest,
    /// The object's declared length exceeds the caller's per-object bound; not corruption.
    ObjectOverLimit,
    /// Access or layout did not permit verification; not missing and not verified.
    Unreadable,
}
impl CustodyObjectState {
    /// Stable spelling, avoiding any event-truth or absence classification.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Deleted => "deleted",
            Self::LocallyTombstoned => "locally_tombstoned",
            Self::Missing => "missing",
            Self::Corrupt => "corrupt",
            Self::InvalidManifest => "invalid_manifest",
            Self::ObjectOverLimit => "object_over_limit",
            Self::Unreadable => "unreadable",
        }
    }
}

/// One unique digest, sorted by digest in the report. No object bytes are retained in the report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodyObjectObservation {
    /// Exact selected or transitively referenced object.
    pub digest: ContentDigest,
    /// Whether a local publication record or the caller-verified root scope declares a manifest.
    pub declared_manifest: bool,
    /// Its observed byte-availability state.
    pub state: CustodyObjectState,
    /// Payload length when its envelope and content digest were verified.
    pub verified_payload_bytes: Option<u64>,
    /// Verified direct children, including metadata; empty for opaque or unverifiable objects.
    pub children: Vec<ContentDigest>,
    /// Verified upstream deletion plan or local tombstone-record digest, when denied.
    pub denial_digest: Option<ContentDigest>,
}

/// Where the selected roots' manifest roles came from. Neither variant grants read authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyRootBasis {
    /// Every selected root must have a validated local `.root` record.
    LocalPublicationRecords,
    /// The caller verified these exact manifest roots against its canonical authority.
    /// This crate does not authenticate or replay that authority on the caller's behalf.
    CallerVerifiedAuthority,
}
impl CustodyRootBasis {
    /// Stable distinction between local root records and upstream authority declarations.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalPublicationRecords => "local_publication_records",
            Self::CallerVerifiedAuthority => "caller_verified_authority",
        }
    }
}

/// Immutable, bounded observations of a selected publication closure. Construction is private.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalCustodyAudit {
    root_basis: CustodyRootBasis,
    roots: Vec<ContentDigest>,
    objects: Vec<CustodyObjectObservation>,
    publication_records: usize,
    local_tombstones: usize,
    charged_read_bytes: u64,
    peak_reserved_read_bytes: u64,
    io_calls: u64,
    edges: usize,
}
impl LocalCustodyAudit {
    /// The selected roots' manifest-role basis, not a newly established authority claim.
    pub const fn root_basis(&self) -> CustodyRootBasis { self.root_basis }
    /// Exact sorted selected roots. No root was silently filtered.
    pub fn roots(&self) -> &[ContentDigest] { &self.roots }
    /// Complete observations of every discovered object, including failures.
    pub fn objects(&self) -> &[CustodyObjectObservation] { &self.objects }
    /// Publication records compared in each metadata pass, including aliases.
    pub const fn publication_records(&self) -> usize { self.publication_records }
    /// Local tombstone records compared in each metadata pass.
    pub const fn local_tombstones(&self) -> usize { self.local_tombstones }
    /// Successfully returned read bytes plus full reserved allowances for failed reads.
    /// Includes spool headers and bounded probes; this is an upper bound, not allocator usage.
    pub const fn charged_read_bytes(&self) -> u64 { self.charged_read_bytes }
    /// Largest charged byte total while one bounded read allowance was reserved.
    /// This is the required reservation envelope of this run, not resident memory.
    pub const fn peak_reserved_read_bytes(&self) -> u64 { self.peak_reserved_read_bytes }
    /// Charged filesystem calls, including EOF directory probes and unsuccessful calls.
    pub const fn io_calls(&self) -> u64 { self.io_calls }
    /// Inspected manifest edges; shared references still cost one edge each.
    pub const fn edges(&self) -> usize { self.edges }
    /// Every discovered manifest was expanded. False means undiscovered descendants may exist.
    pub fn manifest_expansion_complete(&self) -> bool {
        self.objects.iter().all(|o| !o.declared_manifest || o.state == CustodyObjectState::Verified)
    }
    /// All selected publication-closure bytes verified during this bounded sequential read.
    /// Not a lease, atomic snapshot, remote-retrieval proof, or complete semantic provenance proof.
    pub fn all_verified(&self) -> bool {
        self.objects.iter().all(|o| o.state == CustodyObjectState::Verified)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Catalogue {
    records: BTreeMap<SlotName, (ContentDigest, u64, ContentDigest)>,
    manifests: BTreeMap<ContentDigest, u64>,
    tombstones: BTreeMap<ContentDigest, ContentDigest>,
}

fn sha(d: ContentDigest) -> bool {
    d.algorithm() == DigestAlgorithm::Sha256 && d.bytes() != [0; 32]
}
fn check(cancelled: &(impl Fn() -> bool + Sync)) -> Result<(), CustodyAuditError> {
    if cancelled() { Err(CustodyAuditError::Cancelled) } else { Ok(()) }
}
fn bounded(value: usize, limit: usize, what: &'static str) -> Result<(), CustodyAuditError> {
    if value > limit { Err(CustodyAuditError::Limit(what)) } else { Ok(()) }
}

// Reconstruct using the existing public encoder: no permissive parallel record interpretation.
fn root_record(bytes: &[u8], slot: &SlotName) -> Result<(ContentDigest, u64), CustodyAuditError> {
    let invalid = || CustodyAuditError::CatalogueInvalid;
    let mut d = CanonicalDecoder::new(bytes);
    if d.text().map_err(|_| invalid())? != LOCAL_ROOT_RECORD_DOMAIN
        || d.u64().map_err(|_| invalid())? != LOCAL_ROOT_RECORD_FORMAT_VERSION
        || d.text().map_err(|_| invalid())? != slot.as_str()
    { return Err(invalid()); }
    let root = d.digest().map_err(|_| invalid())?;
    let count = d.u64().map_err(|_| invalid())?;
    if !sha(root) || count > fss_object::MAX_MANIFEST_CHILDREN as u64
        || root_record_bytes(slot, root, count as usize).map_err(|_| invalid())?.as_slice() != bytes
    { return Err(invalid()); }
    Ok((root, count))
}
fn tombstone_record(bytes: &[u8]) -> Result<(), CustodyAuditError> {
    let invalid = || CustodyAuditError::CatalogueInvalid;
    let mut d = CanonicalDecoder::new(bytes);
    if d.text().map_err(|_| invalid())? != LOCAL_TOMBSTONE_RECORD_DOMAIN
        || d.u64().map_err(|_| invalid())? != LOCAL_ROOT_RECORD_FORMAT_VERSION
    { return Err(invalid()); }
    let record = TombstoneRecord::from_canonical_bytes(d.bytes().map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    if tombstone_record_bytes(&record).map_err(|_| invalid())?.as_slice() != bytes { return Err(invalid()); }
    Ok(())
}
fn small_read(io: &dyn SpoolIo, path: &Path, maximum: u64) -> Result<Vec<u8>, CustodyAuditError> {
    let mut file = io.open_read(path).map_err(|_| CustodyAuditError::CatalogueInvalid)?;
    let bytes = io.read_bounded(&mut file, maximum + 1)
        .map_err(|_| CustodyAuditError::CatalogueInvalid)?;
    if bytes.len() as u64 > maximum { return Err(CustodyAuditError::CatalogueInvalid); }
    Ok(bytes)
}

fn catalogue(io: &dyn SpoolIo, root: &Path, limit: usize) -> Result<Catalogue, CustodyAuditError> {
    let invalid = || CustodyAuditError::CatalogueInvalid;
    if !io.symlink_metadata(root).map_err(|_| invalid())?.file_type().is_dir() {
        return Err(invalid());
    }
    let mut result = Catalogue {
        records: BTreeMap::new(), manifests: BTreeMap::new(), tombstones: BTreeMap::new(),
    };
    for directory in [LOCAL_ROOTS_DIR, LOCAL_TOMBSTONES_DIR] {
        let dir = root.join(directory);
        if !io.symlink_metadata(&dir).map_err(|_| invalid())?.file_type().is_dir() {
            return Err(invalid());
        }
        let mut entries = io.read_dir(&dir).map_err(|_| invalid())?;
        let mut names = BTreeSet::new();
        while let Some(entry) = io.next_dir_entry(&mut entries) {
            let entry = entry.map_err(|_| invalid())?;
            bounded(names.len() + 1, limit, "catalogue_entries")?;
            if !io.entry_file_type(&entry).map_err(|_| invalid())?.is_file() {
                return Err(invalid());
            }
            let name = entry.file_name().into_string().map_err(|_| invalid())?;
            if !names.insert(name) { return Err(invalid()); }
        }
        for name in names {
            let path = dir.join(&name);
            // Recheck after enumeration; never deliberately follow a substituted symlink.
            if !io.symlink_metadata(&path).map_err(|_| invalid())?.file_type().is_file() {
                return Err(invalid());
            }
            if directory == LOCAL_ROOTS_DIR {
                if name.ends_with(".root.tmp") || name.ends_with(".root.indeterminate") {
                    return Err(CustodyAuditError::PublicationInFlight);
                }
                let slot = SlotName::parse(name.strip_suffix(ROOT_RECORD_SUFFIX).ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
                let bytes = small_read(io, &path, MAX_ROOT_RECORD_BYTES)?;
                let (root, count) = root_record(&bytes, &slot)?;
                if result.manifests.insert(root, count).is_some_and(|old| old != count) {
                    return Err(invalid());
                }
                result.records.insert(slot, (root, count, ContentDigest::sha256(&bytes)));
            } else {
                let stem = name.strip_suffix(TOMBSTONE_RECORD_SUFFIX).ok_or_else(invalid)?;
                let (algorithm, hex) = stem.split_once('-').ok_or_else(invalid)?;
                let digest = ContentDigest::parse(format!("{algorithm}:{hex}")).map_err(|_| invalid())?;
                if !sha(digest) || digest.to_text().replacen(':', "-", 1) != stem { return Err(invalid()); }
                let bytes = small_read(io, &path, MAX_TOMBSTONE_RECORD_BYTES)?;
                tombstone_record(&bytes)?;
                result.tombstones.insert(digest, ContentDigest::sha256(&bytes));
            }
        }
    }
    Ok(result)
}

fn classify(error: LocalPublicationError) -> CustodyObjectState {
    match error {
        LocalPublicationError::Spool(SpoolError::Missing(_))
        | LocalPublicationError::Spool(SpoolError::Corrupt { kind: CorruptionKind::Vanished, .. }) => CustodyObjectState::Missing,
        LocalPublicationError::Spool(SpoolError::Corrupt {
            kind: CorruptionKind::DeclaredLengthExceedsLimit { .. }, ..
        }) => CustodyObjectState::ObjectOverLimit,
        LocalPublicationError::Spool(SpoolError::Corrupt { .. }) => CustodyObjectState::Corrupt,
        _ => CustodyObjectState::Unreadable,
    }
}

/// Verify only the union closure of `selected_roots` through caller-owned I/O and cancellation.
/// `denied` comes from the caller's verified deletion authority (object -> deletion plan digest).
/// It only narrows reads and cannot grant access. Local tombstones independently deny reads.
///
/// The whole root-record catalogue supplies manifest roles; payloads outside the selected closure
/// are NOT scanned. Two equal catalogue observations bracket the payload walk. An unverified
/// manifest ends that branch explicitly; other discoverable objects are still audited. Aggregate
/// exhaustion, cancellation, malformed catalogues and observed catalogue changes return no report.
/// No successful result authorizes exports, proves event truth, or upgrades durability.
pub fn audit_local_roots(
    io: &dyn SpoolIo,
    root: &Path,
    selected_roots: &[ContentDigest],
    denied: &BTreeMap<ContentDigest, ContentDigest>,
    limits: CustodyAuditLimits,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<LocalCustodyAudit, CustodyAuditError> {
    audit_roots(io, root, selected_roots, denied, limits, cancelled,
        CustodyRootBasis::LocalPublicationRecords)
}

/// Audit exact manifest roots selected by a caller that has verified their canonical authority.
///
/// Event revisions may commit an immutable manifest through an `EvidenceDeltaBatch` without a
/// separate local `.root` slot. This entry point declares ONLY the selected roots as manifests;
/// descendants still require their own local publication records or membership in the selected
/// root set. Merely parsing a leaf as a manifest never authorizes expansion.
///
/// The caller MUST resolve every root against its verified authority, apply its deletion and
/// privacy policy before calling, and revalidate that same authority/deletion basis afterwards.
/// This function verifies bytes, not a ledger, authentication, publication durability or access
/// permission. The report records that distinction through [`CustodyRootBasis`]. No root record
/// is manufactured and no existing durable format changes. Use [`audit_local_roots`] when local
/// root records, rather than a separately verified authority, own the root-selection contract.
///
/// Missing or denied selected roots remain declared manifests with incomplete expansion. A
/// local record, when present, still constrains the root's child count; authority selection does
/// not override corrupt, pending, changed or conflicting local metadata. Both modes use the
/// same metered walk, limits, cancellation, local tombstone checks and failure classifications.
pub fn audit_authority_roots(
    io: &dyn SpoolIo,
    root: &Path,
    selected_roots: &[ContentDigest],
    denied: &BTreeMap<ContentDigest, ContentDigest>,
    limits: CustodyAuditLimits,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<LocalCustodyAudit, CustodyAuditError> {
    audit_roots(io, root, selected_roots, denied, limits, cancelled,
        CustodyRootBasis::CallerVerifiedAuthority)
}

fn audit_roots(
    io: &dyn SpoolIo,
    root: &Path,
    selected_roots: &[ContentDigest],
    denied: &BTreeMap<ContentDigest, ContentDigest>,
    limits: CustodyAuditLimits,
    cancelled: &(impl Fn() -> bool + Sync),
    root_basis: CustodyRootBasis,
) -> Result<LocalCustodyAudit, CustodyAuditError> {
    check(cancelled)?;
    limits.validate()?;
    if selected_roots.is_empty() || selected_roots.len() > MAX_AUDIT_ROOTS
        || denied.len() > MAX_AUDIT_OBJECTS
        || selected_roots.iter().any(|d| !sha(*d))
        || denied.iter().any(|(d, proof)| !sha(*d) || !sha(*proof))
    { return Err(CustodyAuditError::InvalidRequest); }
    let roots: BTreeSet<_> = selected_roots.iter().copied().collect();
    if roots.len() != selected_roots.len() { return Err(CustodyAuditError::InvalidRequest); }
    bounded(roots.len(), limits.max_objects, "objects")?;
    let metered = AuditIo::new(io, limits, cancelled);
    let result = walk(&metered, root, roots, denied, limits, cancelled, root_basis);
    // Do not misclassify cancelled/over-budget reads as missing metadata or corrupt content.
    metered.check()?;
    result
}

fn walk(
    io: &AuditIo<'_, impl Fn() -> bool + Sync>,
    root: &Path,
    roots: BTreeSet<ContentDigest>,
    denied: &BTreeMap<ContentDigest, ContentDigest>,
    limits: CustodyAuditLimits,
    cancelled: &(impl Fn() -> bool + Sync),
    root_basis: CustodyRootBasis,
) -> Result<LocalCustodyAudit, CustodyAuditError> {
    let before = catalogue(io, root, limits.max_catalogue_entries)?;
    if root_basis == CustodyRootBasis::LocalPublicationRecords
        && roots.iter().any(|d| !before.manifests.contains_key(d))
    {
        return Err(CustodyAuditError::RootNotPublished);
    }
    let mut seen = roots.clone();
    let mut pending = roots.clone();
    let mut objects = BTreeMap::new();
    let mut edges = 0_usize;
    while let Some(digest) = pending.pop_first() {
        check(cancelled)?;
        let expected_count = before.manifests.get(&digest);
        let declared_manifest = expected_count.is_some()
            || (root_basis == CustodyRootBasis::CallerVerifiedAuthority && roots.contains(&digest));
        let mut row = CustodyObjectObservation {
            digest, declared_manifest, state: CustodyObjectState::Unreadable,
            verified_payload_bytes: None, children: Vec::new(), denial_digest: None,
        };
        if let Some(proof) = denied.get(&digest) {
            row.state = CustodyObjectState::Deleted;
            row.denial_digest = Some(*proof);
        } else if let Some(proof) = before.tombstones.get(&digest) {
            row.state = CustodyObjectState::LocallyTombstoned;
            row.denial_digest = Some(*proof);
        } else {
            match read_verified_with_io(root, digest, limits.max_object_bytes, io) {
                Err(error) => { io.check()?; row.state = classify(error); }
                Ok(bytes) => {
                    io.check()?;
                    row.verified_payload_bytes = Some(bytes.len() as u64);
                    row.state = CustodyObjectState::Verified;
                    if declared_manifest {
                        match ObjectManifest::from_canonical_bytes(&bytes) {
                            Ok(manifest) if manifest.root() == digest
                                && expected_count.is_none_or(|count| manifest.children().len() as u64 == *count) => {
                                edges = edges.checked_add(manifest.children().len())
                                    .ok_or(CustodyAuditError::Limit("edges"))?;
                                bounded(edges, limits.max_edges, "edges")?;
                                for child in manifest.children() {
                                    check(cancelled)?;
                                    if !sha(*child) { return Err(CustodyAuditError::CatalogueInvalid); }
                                    if !seen.contains(child) {
                                        bounded(seen.len() + 1, limits.max_objects, "objects")?;
                                        seen.insert(*child);
                                        pending.insert(*child);
                                    }
                                }
                                row.children = manifest.children().to_vec();
                            }
                            _ => row.state = CustodyObjectState::InvalidManifest,
                        }
                    }
                }
            }
        }
        objects.insert(digest, row);
    }
    let after = catalogue(io, root, limits.max_catalogue_entries)?;
    if before != after { return Err(CustodyAuditError::CatalogueChanged); }
    io.check()?;
    check(cancelled)?;
    Ok(LocalCustodyAudit {
        root_basis,
        roots: roots.into_iter().collect(),
        objects: objects.into_values().collect(),
        publication_records: before.records.len(),
        local_tombstones: before.tombstones.len(),
        charged_read_bytes: io.bytes(),
        peak_reserved_read_bytes: io.peak(),
        io_calls: io.calls(),
        edges,
    })
}

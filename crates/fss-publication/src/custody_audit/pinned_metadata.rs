#![forbid(unsafe_code)]
//! Read-only metadata from exact published slots, with optional bounded namespace discovery.
//!
//! A root record admits one canonical manifest. Only that manifest and its typed metadata
//! may be read; its other children are checked for local deletion markers, never hydrated.
//! All admitted metadata and slot bindings are checked again before a result is released.
//! These bounded observations detect observed changes, not an atomic filesystem snapshot,
//! successful source retrieval, durability, or permission to disclose source bytes.

mod namespace;
pub use namespace::{NamespaceObservation, NamespaceRootRecord};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::path::Path;

use fss_core::ContentDigest;
use fss_object::{ObjectManifest, SpoolIo};

use super::{CustodyAuditError, CustodyAuditLimits, io::AuditIo, root_record, sha, small_read};
use crate::{
    LOCAL_ROOTS_DIR, LOCAL_TOMBSTONES_DIR, MAX_ROOT_RECORD_BYTES, ROOT_INDETERMINATE_SUFFIX,
    ROOT_RECORD_SUFFIX, ROOT_TEMP_SUFFIX, SlotName, TOMBSTONE_RECORD_SUFFIX, read_verified_with_io,
};

/// One request's aggregate work, including the final revalidation pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataReadUsage {
    /// Actual charged file-read bytes, including native envelope headers.
    pub read_bytes: u64,
    /// All filesystem calls, including absent-marker probes.
    pub io_calls: u64,
    /// Distinct manifest and typed-metadata objects read; source children are excluded.
    pub metadata_objects: usize,
    /// Largest aggregate reservation, before unused bounded-read allowance was refunded.
    pub peak_reserved_read_bytes: u64,
    /// Exact slot/root bindings revalidated.
    pub pinned_roots: usize,
    /// Distinct references checked for local deletion markers on both passes.
    pub reference_checks: usize,
}

/// A payload-free refusal. No partial result is a successful metadata observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PinnedMetadataError {
    /// Invalid limits, exhausted shared allowance, cancellation, or I/O contract violation.
    Audit(CustodyAuditError),
    /// A selected slot is absent, malformed, or does not bind the exact requested root.
    RootBinding,
    /// A manifest or metadata envelope could not be read and rehashed under its exact digest.
    MetadataUnavailable,
    /// A manifest is noncanonical, inconsistent with its root record, or not admitted.
    MetadataInvalid,
    /// A local tombstone or pending deletion marker denies a referenced object.
    Tombstoned,
    /// A selected slot changed during the observation.
    Changed,
}
impl PinnedMetadataError {
    /// Stable payload-free refusal identifier.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Audit(error) => error.reason(),
            Self::RootBinding => "recording_root_binding_unverifiable",
            Self::MetadataUnavailable => "recording_metadata_unavailable",
            Self::MetadataInvalid => "recording_metadata_invalid",
            Self::Tombstoned => "recording_reference_tombstoned",
            Self::Changed => "recording_metadata_changed",
        }
    }
}
impl fmt::Display for PinnedMetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}
impl std::error::Error for PinnedMetadataError {}
impl From<CustodyAuditError> for PinnedMetadataError {
    fn from(error: CustodyAuditError) -> Self {
        Self::Audit(error)
    }
}

type Result<T> = std::result::Result<T, PinnedMetadataError>;
type RootBinding = (ContentDigest, u64, ContentDigest);

/// A request-owned, metered, read-only capability for exactly pinned published metadata.
///
/// This type has no arbitrary object-read method, publisher opener, recovery hook, or writer
/// callback. Call [`Self::finish`] before releasing a response. A successful intermediate read
/// alone is not a revalidated observation. The caller supplies semantic metadata verification.
pub struct PinnedMetadataReader<'a, F> {
    root: &'a Path,
    io: AuditIo<'a, F>,
    limits: CustodyAuditLimits,
    bindings: BTreeMap<SlotName, RootBinding>,
    manifests: BTreeMap<ContentDigest, ObjectManifest>,
    objects: BTreeSet<ContentDigest>,
    references: BTreeSet<ContentDigest>,
    edges: usize,
    namespace: Option<Result<namespace::NamespaceWitness>>,
}
impl<F> fmt::Debug for PinnedMetadataReader<'_, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedMetadataReader")
            .field("pinned_roots", &self.bindings.len())
            .field("metadata_objects", &self.objects.len())
            .finish_non_exhaustive()
    }
}

impl<'a, F: Fn() -> bool + Sync> PinnedMetadataReader<'a, F> {
    /// Open no files for writing and acquire no lock. Limits never refill across reads or passes.
    pub fn new(
        io: &'a dyn SpoolIo,
        root: &'a Path,
        limits: CustodyAuditLimits,
        cancelled: &'a F,
    ) -> Result<Self> {
        limits.validate()?;
        let reader = Self {
            root,
            io: AuditIo::new(io, limits, cancelled),
            limits,
            bindings: BTreeMap::new(),
            manifests: BTreeMap::new(),
            objects: BTreeSet::new(),
            references: BTreeSet::new(),
            edges: 0,
            namespace: None,
        };
        let result = reader.layout();
        reader.io.check()?;
        result?;
        Ok(reader)
    }

    /// Admit only a manifest whose exact digest is presently named by the exact slot record.
    /// Every direct child is checked for a local tombstone without reading its payload.
    pub fn manifest(&mut self, slot: &SlotName, expected: ContentDigest) -> Result<ObjectManifest> {
        let result = self.read_manifest(slot, expected);
        self.io.check()?;
        result
    }

    /// Read only the separately typed metadata of a manifest already admitted by this reader.
    pub fn metadata(&mut self, manifest: &ObjectManifest) -> Result<Vec<u8>> {
        self.io.check()?;
        if self.manifests.get(&manifest.root()) != Some(manifest) {
            return Err(PinnedMetadataError::MetadataInvalid);
        }
        let digest = manifest
            .metadata_digest()
            .ok_or(PinnedMetadataError::MetadataInvalid)?;
        let result = self.payload(digest);
        self.io.check()?;
        result
    }

    /// Rehash admitted metadata and repeat every exact slot, tombstone and namespace observation.
    /// Consumes the capability so a caller cannot refill or reuse its request budget.
    pub fn finish(self) -> Result<MetadataReadUsage> {
        let result = self.revalidate();
        self.io.check()?;
        result?;
        Ok(MetadataReadUsage {
            read_bytes: self.io.bytes(),
            io_calls: self.io.calls(),
            metadata_objects: self.objects.len(),
            peak_reserved_read_bytes: self.io.peak(),
            pinned_roots: self.bindings.len(),
            reference_checks: self.references.len(),
        })
    }

    fn layout(&self) -> Result<()> {
        for directory in [
            self.root.to_path_buf(),
            self.root.join(LOCAL_ROOTS_DIR),
            self.root.join(LOCAL_TOMBSTONES_DIR),
        ] {
            let metadata = self
                .io
                .symlink_metadata(&directory)
                .map_err(|_| CustodyAuditError::CatalogueInvalid)?;
            if !metadata.file_type().is_dir() {
                return Err(CustodyAuditError::CatalogueInvalid.into());
            }
        }
        self.io.check()?;
        Ok(())
    }

    fn absent(&self, path: &Path, present: PinnedMetadataError) -> Result<()> {
        match self.io.symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(present),
            Err(_) => Err(CustodyAuditError::CatalogueInvalid.into()),
        }
    }

    fn binding(&self, slot: &SlotName) -> Result<RootBinding> {
        self.io.check()?;
        let name = format!("{}{ROOT_RECORD_SUFFIX}", slot.as_str());
        let directory = self.root.join(LOCAL_ROOTS_DIR);
        for suffix in [ROOT_TEMP_SUFFIX, ROOT_INDETERMINATE_SUFFIX] {
            self.absent(
                &directory.join(format!("{name}{suffix}")),
                CustodyAuditError::PublicationInFlight.into(),
            )?;
        }
        let path = directory.join(name);
        if !self
            .io
            .symlink_metadata(&path)
            .map_err(|_| PinnedMetadataError::RootBinding)?
            .file_type()
            .is_file()
        {
            return Err(PinnedMetadataError::RootBinding);
        }
        let bytes = small_read(&self.io, &path, MAX_ROOT_RECORD_BYTES)?;
        let (root, count) = root_record(&bytes, slot)?;
        Ok((root, count, ContentDigest::sha256(&bytes)))
    }

    fn not_tombstoned(&self, digest: ContentDigest) -> Result<()> {
        if !sha(digest) {
            return Err(PinnedMetadataError::MetadataInvalid);
        }
        let name = format!(
            "{}{TOMBSTONE_RECORD_SUFFIX}",
            digest.to_text().replacen(':', "-", 1)
        );
        for suffix in ["", ROOT_TEMP_SUFFIX, ROOT_INDETERMINATE_SUFFIX] {
            self.absent(
                &self
                    .root
                    .join(LOCAL_TOMBSTONES_DIR)
                    .join(format!("{name}{suffix}")),
                PinnedMetadataError::Tombstoned,
            )?;
        }
        self.io.check()?;
        Ok(())
    }

    fn reference(&mut self, digest: ContentDigest) -> Result<()> {
        if !self.references.contains(&digest) {
            self.not_tombstoned(digest)?;
            self.references.insert(digest);
        }
        Ok(())
    }

    fn payload(&mut self, digest: ContentDigest) -> Result<Vec<u8>> {
        self.io.check()?;
        if !self.objects.contains(&digest) && self.objects.len() >= self.limits.max_objects {
            return Err(CustodyAuditError::Limit("metadata_objects").into());
        }
        self.reference(digest)?;
        self.objects.insert(digest);
        self.verified_payload(digest)
    }

    fn verified_payload(&self, digest: ContentDigest) -> Result<Vec<u8>> {
        let result =
            read_verified_with_io(self.root, digest, self.limits.max_object_bytes, &self.io)
                .map_err(|_| PinnedMetadataError::MetadataUnavailable);
        self.io.check()?;
        result
    }

    fn read_manifest(
        &mut self,
        slot: &SlotName,
        expected: ContentDigest,
    ) -> Result<ObjectManifest> {
        self.io.check()?;
        if !sha(expected) {
            return Err(CustodyAuditError::InvalidRequest.into());
        }
        if let Some(binding) = self.bindings.get(slot) {
            if binding.0 != expected {
                return Err(PinnedMetadataError::RootBinding);
            }
            return self
                .manifests
                .get(&expected)
                .cloned()
                .ok_or(PinnedMetadataError::MetadataInvalid);
        }
        if self.bindings.len() >= self.limits.max_catalogue_entries {
            return Err(CustodyAuditError::Limit("pinned_roots").into());
        }
        let binding = self.binding(slot)?;
        if binding.0 != expected {
            return Err(PinnedMetadataError::RootBinding);
        }
        let bytes = self.payload(expected)?;
        let manifest = ObjectManifest::from_canonical_bytes(&bytes)
            .map_err(|_| PinnedMetadataError::MetadataInvalid)?;
        if manifest.root() != expected || manifest.children().len() as u64 != binding.1 {
            return Err(PinnedMetadataError::MetadataInvalid);
        }
        let edges = self
            .edges
            .checked_add(manifest.children().len())
            .filter(|count| *count <= self.limits.max_edges)
            .ok_or(CustodyAuditError::Limit("manifest_edges"))?;
        for child in manifest.children() {
            self.io.check()?;
            self.reference(*child)?;
        }
        self.edges = edges;
        self.bindings.insert(slot.clone(), binding);
        self.manifests.insert(expected, manifest.clone());
        Ok(manifest)
    }

    fn revalidate(&self) -> Result<()> {
        if let Some(Err(error)) = &self.namespace {
            return Err(error.clone());
        }
        self.layout()?;
        for digest in &self.objects {
            self.io.check()?;
            self.verified_payload(*digest)?;
        }
        for digest in &self.references {
            self.not_tombstoned(*digest)?;
        }
        for (slot, expected) in &self.bindings {
            if self.binding(slot)? != *expected {
                return Err(PinnedMetadataError::Changed);
            }
        }
        self.revalidate_namespace()?;
        self.layout()?;
        self.io.check()?;
        Ok(())
    }
}

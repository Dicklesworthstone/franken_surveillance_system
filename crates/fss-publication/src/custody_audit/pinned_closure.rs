#![forbid(unsafe_code)]
//! Exact-slot flat closure retrieval without opening a publisher or scanning an archive.
//!
//! Each selected root is completed and revalidated before the next begins. The request's
//! byte, I/O, object, edge and root allowances never refill between roots. Only explicitly
//! admitted direct children can be read. Child payloads are opaque; manifest-shaped bytes
//! do not confer a manifest role or permission to traverse another object graph.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use fss_core::ContentDigest;
use fss_object::{ObjectManifest, SpoolIo};

use super::pinned_metadata::{PinnedMetadataError, PinnedMetadataReader};
use super::{CustodyAuditError, CustodyAuditLimits};
use crate::SlotName;

/// Cumulative accounting across all completed and current selected flat closures.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PinnedClosureUsage {
    /// Charged returned bytes, with failed bounded reads retaining their reservation.
    pub read_bytes: u64,
    /// All filesystem calls, including absent-marker probes and final revalidation.
    pub io_calls: u64,
    /// Largest charged read reservation, not resident memory.
    pub peak_reserved_read_bytes: u64,
    /// Completed exact slot/root observations; an unfinished root is not included.
    pub completed_roots: usize,
    /// Object admissions, deduplicated within each closure, never across separate roots.
    pub objects: usize,
    /// Inspected direct manifest edges, including shared children.
    pub edges: usize,
    /// Selected digest deletion checks, deduplicated within each completed closure.
    pub reference_checks: usize,
}

/// No failed operation releases a complete-closure observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PinnedClosureError {
    /// Exact publication, object integrity, local deletion, cancellation or I/O refusal.
    Observation(PinnedMetadataError),
    /// A new root was requested before completion, or the supplied manifest is not admitted.
    Scope,
    /// At least one direct child was not read; this is not a complete flat closure.
    Incomplete,
    /// A previous refusal permanently stopped this request capability.
    Stopped,
}
impl PinnedClosureError {
    /// Stable payload-free reason; paths and source bytes are never printed.
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Observation(PinnedMetadataError::MetadataUnavailable) => {
                "selected_closure_object_unavailable"
            }
            Self::Observation(error) => error.reason(),
            Self::Scope => "selected_closure_scope_mismatch",
            Self::Incomplete => "selected_closure_incomplete",
            Self::Stopped => "selected_closure_stopped",
        }
    }
}
impl fmt::Display for PinnedClosureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}
impl std::error::Error for PinnedClosureError {}
impl From<PinnedMetadataError> for PinnedClosureError {
    fn from(error: PinnedMetadataError) -> Self {
        Self::Observation(error)
    }
}
impl From<CustodyAuditError> for PinnedClosureError {
    fn from(error: CustodyAuditError) -> Self {
        Self::Observation(error.into())
    }
}
type Result<T> = std::result::Result<T, PinnedClosureError>;

struct ActiveRoot {
    manifest: ObjectManifest,
    read: BTreeSet<ContentDigest>,
}

/// Read-only source capability for a bounded sequence of independently pinned flat closures.
///
/// No directory enumeration, writer lock, staging, recovery, creation or deletion occurs.
/// Call [`Self::finish_root`] before releasing each closure and [`Self::finish`] when the
/// request ends. The caller supplies explicit read authority through the I/O capability and
/// cancellation function, and must enforce its own semantic/ledger/privacy policy.
/// Repeated checks detect observed changes; they are not an atomic filesystem snapshot,
/// a durability certificate, a read lease, or permission to disclose source bytes.
pub struct PinnedClosureReader<'a> {
    root: &'a Path,
    inner: PinnedMetadataReader<'a, dyn Fn() -> bool + Sync + 'a>,
    limits: CustodyAuditLimits,
    completed: PinnedClosureUsage,
    active: Option<ActiveRoot>,
    stopped: bool,
    finalized: Option<PinnedClosureUsage>,
}
impl fmt::Debug for PinnedClosureReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedClosureReader")
            .field("usage", &self.usage())
            .field("active", &self.active.is_some())
            .field("stopped", &self.stopped)
            .finish_non_exhaustive()
    }
}

impl<'a> PinnedClosureReader<'a> {
    /// Validate an existing archive layout without opening a writer or creating missing paths.
    pub fn new(
        io: &'a dyn SpoolIo,
        root: &'a Path,
        limits: CustodyAuditLimits,
        cancelled: &'a (dyn Fn() -> bool + Sync),
    ) -> Result<Self> {
        Ok(Self {
            root,
            inner: PinnedMetadataReader::new(io, root, limits, cancelled)?,
            limits,
            completed: PinnedClosureUsage::default(),
            active: None,
            stopped: false,
            finalized: None,
        })
    }

    /// Exact supplied archive owner, never an inferred or created destination.
    pub fn root_dir(&self) -> &Path {
        self.root
    }

    /// Immutable request allowances; no method replenishes these across roots or reads.
    pub const fn limits(&self) -> CustodyAuditLimits {
        self.limits
    }

    /// Charged request work, including any unfinished current root.
    pub fn usage(&self) -> PinnedClosureUsage {
        let observed = self.inner.usage();
        PinnedClosureUsage {
            read_bytes: observed.read_bytes,
            io_calls: observed.io_calls,
            peak_reserved_read_bytes: observed.peak_reserved_read_bytes,
            objects: self.completed.objects + observed.metadata_objects,
            edges: self.completed.edges
                + self
                    .active
                    .as_ref()
                    .map_or(0, |root| root.manifest.children().len()),
            reference_checks: self.completed.reference_checks + observed.reference_checks,
            ..self.completed
        }
    }

    fn outcome<T>(&mut self, result: Result<T>) -> Result<T> {
        if result.is_err() {
            self.stopped = true;
        }
        result
    }

    /// Admit one exact currently published root and its directly declared immutable children.
    pub fn manifest(&mut self, slot: &SlotName, expected: ContentDigest) -> Result<ObjectManifest> {
        if self.stopped || self.finalized.is_some() {
            return Err(PinnedClosureError::Stopped);
        }
        let result = (|| {
            if self.active.is_some() {
                return Err(PinnedClosureError::Scope);
            }
            if self.completed.completed_roots >= self.limits.max_catalogue_entries {
                return Err(CustodyAuditError::Limit("pinned_roots").into());
            }
            self.inner.closure_allowances(
                self.limits.max_objects - self.completed.objects,
                self.limits.max_edges - self.completed.edges,
            )?;
            let manifest = self.inner.manifest(slot, expected)?;
            self.active = Some(ActiveRoot {
                manifest: manifest.clone(),
                read: BTreeSet::new(),
            });
            Ok(manifest)
        })();
        self.outcome(result)
    }

    /// Rehash one explicitly declared child under both per-read and whole-request ceilings.
    /// Unrelated or transitively guessed digests are refused before their payload is opened.
    pub fn child(
        &mut self,
        manifest: &ObjectManifest,
        digest: ContentDigest,
        max_bytes: usize,
    ) -> Result<Vec<u8>> {
        if self.stopped || self.finalized.is_some() {
            return Err(PinnedClosureError::Stopped);
        }
        let result = (|| {
            let active = self.active.as_mut().ok_or(PinnedClosureError::Scope)?;
            if &active.manifest != manifest || !manifest.children().contains(&digest) {
                return Err(PinnedClosureError::Scope);
            }
            let bytes = self.inner.child(manifest, digest, max_bytes)?;
            active.read.insert(digest);
            Ok(bytes)
        })();
        self.outcome(result)
    }

    /// Complete one flat closure: all children must be read, then all selected objects are
    /// rehashed and exact root/deletion observations repeated. No previous root is reread.
    pub fn finish_root(&mut self) -> Result<PinnedClosureUsage> {
        self.finish_root_with(&|| false)
    }

    /// Complete a root while also checking the caller's current semantic authority around
    /// every rehashed object and metadata stage. This probe need not be thread-safe; the
    /// reader's original request cancellation independently gates every filesystem call.
    pub fn finish_root_with(&mut self, cancelled: &dyn Fn() -> bool) -> Result<PinnedClosureUsage> {
        if self.stopped || self.finalized.is_some() {
            return Err(PinnedClosureError::Stopped);
        }
        let result = (|| {
            let active = self.active.as_ref().ok_or(PinnedClosureError::Scope)?;
            if active.read.len() != active.manifest.children().len() {
                return Err(PinnedClosureError::Incomplete);
            }
            let edges = active.manifest.children().len();
            let observed = self.inner.closure_checkpoint(cancelled)?;
            self.completed.completed_roots += 1;
            self.completed.objects += observed.metadata_objects;
            self.completed.edges += edges;
            self.completed.reference_checks += observed.reference_checks;
            self.active = None;
            Ok(self.usage())
        })();
        self.outcome(result)
    }

    /// Recheck layout and cancellation, then close this request against further source reads.
    /// Prior payloads are not reread; each root was completed before its bytes were released.
    /// A repeated successful finalize returns the same accounting without new I/O or authority.
    pub fn finalize(&mut self) -> Result<PinnedClosureUsage> {
        if self.stopped {
            return Err(PinnedClosureError::Stopped);
        }
        if let Some(usage) = self.finalized {
            return Ok(usage);
        }
        let result = (|| {
            if self.active.is_some() {
                return Err(PinnedClosureError::Incomplete);
            }
            self.inner.closure_final_check()?;
            let usage = self.usage();
            self.finalized = Some(usage);
            Ok(usage)
        })();
        self.outcome(result)
    }

    /// End the request without refilling its allowance or accepting an unfinished closure.
    pub fn finish(mut self) -> Result<PinnedClosureUsage> {
        self.finalize()
    }
}

#![forbid(unsafe_code)]
//! One literal namespace observation within the exact-metadata reader's shared allowance.

use fss_core::ContentDigest;
use fss_object::SpoolIo;

use super::{PinnedMetadataError, PinnedMetadataReader, Result};
use crate::custody_audit::{CustodyAuditError, MAX_AUDIT_CATALOGUE_ENTRIES};
use crate::{
    LOCAL_ROOTS_DIR, ROOT_INDETERMINATE_SUFFIX, ROOT_RECORD_SUFFIX, ROOT_TEMP_SUFFIX, SlotName,
};

/// One canonical root record. This binding alone does not verify its manifest or children.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceRootRecord {
    /// Exact published slot, sorted lexically within the observation.
    pub slot: SlotName,
    /// Root named by that slot's canonical record.
    pub root: ContentDigest,
    /// Declared manifest child count, checked when the manifest is admitted separately.
    pub child_count: u64,
    /// SHA-256 of the complete canonical root record.
    pub record_digest: ContentDigest,
}

/// Bounded inventory of one literal slot prefix, pending [`PinnedMetadataReader::finish`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceObservation {
    /// Every canonical record selected by the full literal prefix, in slot order.
    pub roots: Vec<NamespaceRootRecord>,
    /// All entries encountered in the roots directory, including unrelated entries.
    pub scanned_entries: usize,
}

pub(super) struct NamespaceWitness {
    prefix: SlotName,
    max_scan_entries: usize,
    max_roots: usize,
    observation: NamespaceObservation,
}

impl<F: Fn() -> bool + Sync + ?Sized> PinnedMetadataReader<'_, F> {
    /// Observe one complete literal slot prefix without opening manifests or source objects.
    ///
    /// The prefix must itself satisfy the slot grammar; it is never a glob or path. Every
    /// directory entry consumes the scan allowance, but only names starting with the full
    /// prefix are inspected. Selected pending, malformed, noncanonical or non-file entries
    /// refuse the observation. Unrelated entry contents and types are never inspected.
    ///
    /// At most one namespace scan may start on a reader. A failed scan cannot be replaced by
    /// a smaller successful observation. [`Self::finish`] repeats the complete scan and exact
    /// record checks under the same nonrefillable byte and I/O allowances. Changes to selected
    /// membership or records refuse the result; unrelated membership changes need not do so.
    pub fn observe_namespace(
        &mut self,
        prefix: &str,
        max_scan_entries: usize,
        max_roots: usize,
    ) -> Result<NamespaceObservation> {
        self.io.check()?;
        if self.namespace.is_some()
            || max_scan_entries > MAX_AUDIT_CATALOGUE_ENTRIES
            || max_roots > MAX_AUDIT_CATALOGUE_ENTRIES
        {
            return Err(CustodyAuditError::InvalidRequest.into());
        }
        let prefix = SlotName::parse(prefix).map_err(|_| CustodyAuditError::InvalidRequest)?;
        let result = self.scan_namespace(&prefix, max_scan_entries, max_roots);
        let result = match self.io.check() {
            Ok(()) => result,
            Err(error) => Err(error.into()),
        };
        self.namespace = Some(
            result
                .as_ref()
                .map(|observation| NamespaceWitness {
                    prefix,
                    max_scan_entries,
                    max_roots,
                    observation: observation.clone(),
                })
                .map_err(Clone::clone),
        );
        result
    }

    pub(super) fn revalidate_namespace(&self) -> Result<()> {
        let Some(witness) = &self.namespace else {
            return Ok(());
        };
        let witness = witness.as_ref().map_err(Clone::clone)?;
        let current =
            self.scan_namespace(&witness.prefix, witness.max_scan_entries, witness.max_roots)?;
        if current.roots != witness.observation.roots {
            return Err(PinnedMetadataError::Changed);
        }
        Ok(())
    }

    fn scan_namespace(
        &self,
        prefix: &SlotName,
        max_scan_entries: usize,
        max_roots: usize,
    ) -> Result<NamespaceObservation> {
        self.io.check()?;
        let invalid = || CustodyAuditError::CatalogueInvalid;
        let directory = self.root.join(LOCAL_ROOTS_DIR);
        if !self
            .io
            .symlink_metadata(&directory)
            .map_err(|_| invalid())?
            .file_type()
            .is_dir()
        {
            return Err(invalid().into());
        }
        let mut entries = self.io.read_dir(&directory).map_err(|_| invalid())?;
        let mut roots = Vec::new();
        let mut scanned_entries = 0usize;
        while let Some(entry) = self.io.next_dir_entry(&mut entries) {
            let entry = entry.map_err(|_| invalid())?;
            if scanned_entries >= max_scan_entries {
                return Err(CustodyAuditError::Limit("namespace_scan_entries").into());
            }
            scanned_entries += 1;
            let name = entry.file_name();
            if !name
                .as_encoded_bytes()
                .starts_with(prefix.as_str().as_bytes())
            {
                continue;
            }
            if roots.len() >= max_roots {
                return Err(CustodyAuditError::Limit("namespace_roots").into());
            }
            let name = name.to_str().ok_or_else(invalid)?;
            if name.ends_with(&format!("{ROOT_RECORD_SUFFIX}{ROOT_TEMP_SUFFIX}"))
                || name.ends_with(&format!("{ROOT_RECORD_SUFFIX}{ROOT_INDETERMINATE_SUFFIX}"))
            {
                return Err(CustodyAuditError::PublicationInFlight.into());
            }
            let slot = SlotName::parse(name.strip_suffix(ROOT_RECORD_SUFFIX).ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
            if !self
                .io
                .entry_file_type(&entry)
                .map_err(|_| invalid())?
                .is_file()
            {
                return Err(invalid().into());
            }
            let (root, child_count, record_digest) = self.binding(&slot)?;
            roots
                .try_reserve(1)
                .map_err(|_| CustodyAuditError::Limit("namespace_roots"))?;
            roots.push(NamespaceRootRecord {
                slot,
                root,
                child_count,
                record_digest,
            });
        }
        roots.sort_unstable_by(|left, right| left.slot.cmp(&right.slot));
        if roots.windows(2).any(|pair| pair[0].slot == pair[1].slot) {
            return Err(invalid().into());
        }
        self.io.check()?;
        Ok(NamespaceObservation {
            roots,
            scanned_entries,
        })
    }
}

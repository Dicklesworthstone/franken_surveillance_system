#![forbid(unsafe_code)]
//! Complete canonical namespace verification borrowed from one request-owned metadata reader.
//!
//! Decode-tick and UTC selection use this same inventory owner. A visitor sees a member only
//! after its page and publication are verified. It cannot finish or refill the reader; the
//! caller must complete all selection and clock checks before one global final revalidation.

use std::collections::BTreeSet;

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_publication::custody_audit::pinned_metadata::{NamespaceObservation, PinnedMetadataReader};

use super::{RecordingDiscoveryError, Result, bounded_vec, checkpoint, digest};
use crate::agent_recordings::RecordingQueryCodec;
use crate::agent_recordings::set::{
    RecordingCatalogPin, RecordingSetCatalog, RecordingSetLocation,
};
use crate::rtsp::recording_archive::{ArchiveCodec, CodecArchiveNamespace};
use crate::rtsp::recording_catalog::hevc::verify_hevc_catalog;
use crate::rtsp::recording_catalog::{CatalogEntry, CatalogError, CatalogScope, verify_catalog};

/// Namespace cardinality ceilings; all actual I/O remains charged by the borrowed reader.
#[derive(Clone, Copy)]
pub(in crate::agent_recordings) struct NamespaceLimits {
    pub max_scan_roots: usize,
    pub max_windows: usize,
    pub max_pages: usize,
}

/// Complete typed metadata inventory, still awaiting the caller's reader.finish().
pub(in crate::agent_recordings) struct VerifiedNamespace {
    pub namespace_digest: ContentDigest,
    pub inventory_digest: ContentDigest,
    pub catalogs: Vec<RecordingSetCatalog>,
    pub references: BTreeSet<ContentDigest>,
    pub scanned_windows: usize,
    pub scanned_root_entries: usize,
}

pub(in crate::agent_recordings) fn read_namespace<C: ArchiveCodec, F: Fn() -> bool + Sync>(
    reader: &mut PinnedMetadataReader<'_, F>,
    codec: RecordingQueryCodec,
    scope: &CatalogScope,
    namespace: CodecArchiveNamespace<C>,
    limits: NamespaceLimits,
    cancelled: &F,
    visit: &mut impl FnMut(&CatalogEntry, RecordingSetLocation) -> Result<()>,
) -> Result<VerifiedNamespace> {
    let max_roots = limits
        .max_windows
        .checked_add(limits.max_pages)
        .ok_or(RecordingDiscoveryError::Limit)?;
    let observation =
        reader.observe_namespace(namespace.prefix(), limits.max_scan_roots, max_roots)?;
    let namespace_digest = namespace.digest();
    let inventory_digest = inventory_digest(namespace_digest, &observation, cancelled)?;
    let mut window_roots = bounded_vec(observation.roots.len().min(limits.max_windows))?;
    let mut page_roots = bounded_vec(observation.roots.len().min(limits.max_pages))?;
    let mut unique_roots = BTreeSet::new();
    for record in &observation.roots {
        checkpoint(cancelled)?;
        let (role, ordinal) = namespace
            .classify_slot(&record.slot)?
            .ok_or(RecordingDiscoveryError::Sequence)?;
        let (target, limit) = match role {
            'w' => {
                if !unique_roots.insert(record.root) {
                    return Err(RecordingDiscoveryError::Sequence);
                }
                (&mut window_roots, limits.max_windows)
            }
            'c' => (&mut page_roots, limits.max_pages),
            _ => return Err(RecordingDiscoveryError::Sequence),
        };
        if target.len() == limit {
            return Err(RecordingDiscoveryError::Limit);
        }
        target.push((ordinal, record));
    }
    window_roots.sort_unstable_by_key(|(ordinal, _)| *ordinal);
    page_roots.sort_unstable_by_key(|(ordinal, _)| *ordinal);
    if window_roots
        .iter()
        .enumerate()
        .any(|(index, (ordinal, _))| index != *ordinal)
    {
        return Err(RecordingDiscoveryError::Sequence);
    }

    let mut catalogs = bounded_vec(page_roots.len())?;
    let mut references = BTreeSet::new();
    let mut indexed = 0_usize;
    let mut last_end = None;
    for (first, record) in page_roots {
        checkpoint(cancelled)?;
        if first != indexed {
            return Err(RecordingDiscoveryError::Sequence);
        }
        let manifest = reader.manifest(&record.slot, record.root)?;
        if manifest.kind() != codec.catalog_kind() {
            return Err(CatalogError::Malformed.into());
        }
        let metadata_digest = manifest.metadata_digest().ok_or(CatalogError::Malformed)?;
        let index = reader.metadata(&manifest)?;
        let entries = match codec {
            RecordingQueryCodec::Avc => {
                let catalog = verify_catalog(&manifest, &index, scope)?;
                let mut entries = bounded_vec(catalog.entries().len())?;
                entries.extend_from_slice(catalog.entries());
                entries
            }
            RecordingQueryCodec::Hevc => {
                let catalog = verify_hevc_catalog(&manifest, &index, scope)?;
                let mut entries = bounded_vec(catalog.entries().len())?;
                entries.extend_from_slice(catalog.entries());
                entries
            }
        };
        let end = first
            .checked_add(entries.len())
            .ok_or(RecordingDiscoveryError::Limit)?;
        if end > window_roots.len() {
            return Err(RecordingDiscoveryError::Sequence);
        }
        references.insert(manifest.root());
        references.insert(metadata_digest);
        references.extend(manifest.children().iter().copied());
        for (ordinal, (entry, (_, expected))) in
            entries.iter().zip(&window_roots[first..end]).enumerate()
        {
            checkpoint(cancelled)?;
            if entry.slot() != &expected.slot || entry.root() != expected.root {
                return Err(CatalogError::WindowMismatch.into());
            }
            let interval = entry.decode_interval();
            if last_end.is_some_and(|previous| previous > interval.start) {
                return Err(RecordingDiscoveryError::Sequence);
            }
            last_end = Some(interval.end);
            let window = reader.manifest(entry.slot(), entry.root())?;
            if window.kind() != codec.window_kind() {
                return Err(CatalogError::WindowMismatch.into());
            }
            references.insert(window.root());
            references.extend(window.children().iter().copied());
            if let Some(metadata) = window.metadata_digest() {
                references.insert(metadata);
            }
            visit(
                entry,
                RecordingSetLocation {
                    catalog_index: catalogs.len(),
                    catalog_root: record.root,
                    ordinal,
                },
            )?;
        }
        indexed = end;
        catalogs.push(RecordingSetCatalog {
            pin: RecordingCatalogPin {
                slot: record.slot.clone(),
                root: record.root,
            },
            metadata_digest,
            scanned_windows: entries.len(),
        });
    }
    if indexed != window_roots.len() {
        return Err(RecordingDiscoveryError::UnindexedWindows);
    }
    Ok(VerifiedNamespace {
        namespace_digest,
        inventory_digest,
        catalogs,
        references,
        scanned_windows: indexed,
        scanned_root_entries: observation.scanned_entries,
    })
}

fn inventory_digest(
    namespace: ContentDigest,
    observation: &NamespaceObservation,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<ContentDigest> {
    let mut encoder = CanonicalEncoder::new();
    encoder.text("fss.agent_recordings.discovery.inventory.v1");
    encoder.digest(namespace);
    encoder.u64(observation.roots.len() as u64);
    for record in &observation.roots {
        checkpoint(cancelled)?;
        encoder.text(record.slot.as_str());
        encoder.digest(record.root);
        encoder.u64(record.child_count);
        encoder.digest(record.record_digest);
    }
    digest(encoder)
}

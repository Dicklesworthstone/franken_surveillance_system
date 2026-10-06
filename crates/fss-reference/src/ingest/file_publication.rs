#![forbid(unsafe_code)]
//! Bounded file-import part publication (fss-lrgio).
//!
//! Parts are independent, durable, ledgered slots. The final file metadata names their exact
//! roots in `FileImportManifest::part_roots`; its publication slot contains the metadata only.
//! Making the parts native children of that slot would flatten the whole transitive closure
//! back into one oversized reachability batch. This module therefore verifies every typed
//! part reference explicitly before publishing the aggregate, and again on `verify`.
//!
//! This publishes custody, not import completion: the owning adapter must still commit its
//! capsule batches and final generation-2 import batch. It grants no effect capability and
//! certifies neither capture time nor coverage. Payloads must already be staged by the caller.
//! Existing flat manifests keep their canonical bytes. The file adapter admits the complete
//! payload/publication quota before staging, commits capsule authority, publishes parts and
//! aggregate through this protocol, and only then commits import completion.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    BatchId, CanonicalEncode, CaptureInterval, ContentDigest, ContractError, DigestAlgorithm,
    EvidenceDelta, EvidenceDeltaBatch, ObjectId, Plane,
};
use fss_object::{MAX_MANIFEST_CHILDREN, ObjectManifest, VerifiedObjectCatalog};
use fss_publication::{
    LocalPublicationError, LocalPublicationState, ROOT_REACHABILITY_FAMILY, RootLedgerReceipt,
    SlotName,
};

use super::file_adapter::{FileImportManifest, FileIngestError};
use super::retained::{MAX_RETAINED_ENTRIES, MAX_RETAINED_MANIFEST_BYTES};
use crate::{ReferenceDeployment, ReplayCx};

/// Maximum number of input payload references, including repetitions before deduplication.
pub const MAX_FILE_PUBLICATION_PAYLOADS: usize = 262_144;
/// Bound on independently published parts and on the final metadata's typed root references.
pub const MAX_FILE_PUBLICATION_PARTS: usize = 16_384;
/// Admission and custody-verification checkpoint, before any publication metadata is staged.
pub const STAGE_FILE_PART_PREFLIGHT: &str = "file_parts:preflight";
/// Checkpoint before each part's stage/publish/ledger operation.
pub const STAGE_FILE_PART_PUBLISH: &str = "file_parts:publish";
/// Checkpoint after all parts are ledgered and before the final metadata root is published.
pub const STAGE_FILE_PART_ROOT: &str = "file_parts:root";
/// Checkpoint during explicit read-only verification of the typed part references.
pub const STAGE_FILE_PART_VERIFY: &str = "file_parts:verify";

fn invalid(detail: &str) -> FileIngestError {
    FileIngestError::CorruptSegment {
        detail: format!("file publication: {detail}"),
    }
}

fn capacity(limit: &'static str, required: usize, available: usize) -> FileIngestError {
    FileIngestError::SpoolCapacityExceeded {
        limit,
        required: required as u64,
        available: available as u64,
    }
}

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<(), FileIngestError> {
    cx.checkpoint(stage)
        .map_err(|_| FileIngestError::CancellationRequested { stage })
}

/// One canonically ordered payload partition. Its slot is derived from the import, not a path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePublicationPart {
    slot: SlotName,
    manifest: ObjectManifest,
}

impl FilePublicationPart {
    /// Exact owner-scoped slot for this ordinal.
    pub fn slot(&self) -> &SlotName {
        &self.slot
    }

    /// Immutable bounded manifest; its children are opaque payloads, not other visible roots.
    pub fn manifest(&self) -> &ObjectManifest {
        &self.manifest
    }
}

/// Immutable, bounded publication plan; it contains no authority to publish or complete an import.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePublicationPlan {
    import_identity: ContentDigest,
    slot: SlotName,
    payloads: Vec<ContentDigest>,
    parts: Vec<FilePublicationPart>,
    child_limit: usize,
}

/// All part roots and the final metadata root are durable and ledgered, not necessarily imported.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilePublicationReceipt {
    /// Per-part receipts in canonical ordinal order; empty for an unchanged flat publication.
    pub parts: Vec<RootLedgerReceipt>,
    /// Final metadata-root receipt. File import completion is a separate authority transition.
    pub root: RootLedgerReceipt,
}

impl FilePublicationPlan {
    /// Plans deterministic sorted partitions without I/O or changing any hard format limit.
    ///
    /// `child_limit` must fit both the caller's manifest and ledger-batch child bounds. Repeated
    /// payload references are deduplicated, but still consume the bounded input-iteration budget.
    /// The final metadata consumes one child slot in the flat case. No iterator size hint is
    /// used for allocation, and an unbounded iterator is refused after one excess reference.
    pub fn new(
        import_identity: ContentDigest,
        payloads: impl IntoIterator<Item = ContentDigest>,
        child_limit: usize,
    ) -> Result<Self, FileIngestError> {
        if import_identity.algorithm() != DigestAlgorithm::Sha256 {
            return Err(ContractError::UnsupportedDigestAlgorithm.into());
        }
        if child_limit == 0 || child_limit > MAX_MANIFEST_CHILDREN {
            return Err(FileIngestError::InvalidLimits {
                detail: "file publication child limit must be in 1..=16384".to_owned(),
            });
        }
        let hex: String = import_identity
            .bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let slot =
            SlotName::parse(&format!("fi-{hex}")).map_err(|_| ContractError::InvalidIdentifier)?;
        let mut unique = BTreeSet::new();
        for (index, digest) in payloads.into_iter().enumerate() {
            if index == MAX_FILE_PUBLICATION_PAYLOADS {
                return Err(capacity(
                    "file_publication_payloads",
                    index + 1,
                    MAX_FILE_PUBLICATION_PAYLOADS,
                ));
            }
            if digest.algorithm() != DigestAlgorithm::Sha256 {
                return Err(ContractError::UnsupportedDigestAlgorithm.into());
            }
            unique.insert(digest);
        }
        let payloads: Vec<_> = unique.into_iter().collect();
        let mut parts = Vec::new();
        if payloads.len() >= child_limit {
            let count = payloads.len().div_ceil(child_limit);
            if count > MAX_FILE_PUBLICATION_PARTS {
                return Err(capacity(
                    "file_publication_parts",
                    count,
                    MAX_FILE_PUBLICATION_PARTS,
                ));
            }
            for (ordinal, children) in payloads.chunks(child_limit).enumerate() {
                let part_slot = SlotName::parse(&format!("fi-{hex}-p{ordinal:06}"))
                    .map_err(|_| ContractError::InvalidIdentifier)?;
                parts.push(FilePublicationPart {
                    manifest: ObjectManifest::new(
                        part_slot.as_str(),
                        children.iter().copied(),
                        None,
                    )?,
                    slot: part_slot,
                });
            }
        }
        Ok(Self {
            import_identity,
            slot,
            payloads,
            parts,
            child_limit,
        })
    }

    /// Final file-import publication slot.
    pub fn slot(&self) -> &SlotName {
        &self.slot
    }

    /// Every deduplicated payload reference, in canonical digest order.
    pub fn payloads(&self) -> &[ContentDigest] {
        &self.payloads
    }

    /// Independently published parts, or an empty slice for the unchanged flat representation.
    pub fn parts(&self) -> &[FilePublicationPart] {
        &self.parts
    }

    /// Exact root list to place in the file metadata before its digest is computed.
    pub fn part_roots(&self) -> Vec<ContentDigest> {
        self.parts.iter().map(|part| part.manifest.root()).collect()
    }

    /// Binds the exact part list and required source chunks into the final publication manifest.
    /// Does not resolve custody or authorize publication. Source metadata must be bounded before
    /// canonical encoding; this method deliberately makes no media-format or completion claim.
    pub fn root_manifest(
        &self,
        metadata: &FileImportManifest,
    ) -> Result<ObjectManifest, FileIngestError> {
        if metadata.part_roots != self.part_roots() {
            return Err(invalid("metadata part roots differ from the exact plan"));
        }
        if metadata.ordered_chunks.len() > MAX_RETAINED_ENTRIES
            || metadata.segment_spans.len() > MAX_RETAINED_ENTRIES
            || metadata.capsule_ids.len() > MAX_RETAINED_ENTRIES
            || metadata.omission_spans.len() > MAX_RETAINED_ENTRIES
            || metadata.format.len() > 256
            || metadata.detector_evidence.len() > 1024
            || metadata.adapter_id.len() > 256
            || metadata.adapter_generation.len() > 256
            || metadata.capture_time_label.len() > 256
            || metadata
                .omission_spans
                .iter()
                .any(|span| span.reason.len() > 1024)
        {
            return Err(invalid(
                "metadata exceeds bounded collection or text limits",
            ));
        }
        if metadata
            .ordered_chunks
            .iter()
            .any(|digest| self.payloads.binary_search(digest).is_err())
        {
            return Err(invalid(
                "source chunk is absent from the planned custody closure",
            ));
        }
        let encoded_size = metadata_encoded_size(metadata)?;
        if encoded_size > MAX_RETAINED_MANIFEST_BYTES {
            return Err(capacity(
                "file_publication_metadata_bytes",
                encoded_size,
                MAX_RETAINED_MANIFEST_BYTES,
            ));
        }
        let bytes = metadata.canonical_bytes();
        if bytes.len() != encoded_size {
            return Err(invalid("file metadata canonical size contract changed"));
        }
        let digest = ContentDigest::sha256(&bytes);
        if self.payloads.binary_search(&digest).is_ok() {
            return Err(invalid("file metadata cannot also be a payload child"));
        }
        let children = if self.parts.is_empty() {
            self.payloads.clone()
        } else {
            Vec::new()
        };
        Ok(ObjectManifest::new(
            self.slot.as_str(),
            children,
            Some(digest),
        )?)
    }

    /// Publishes already-staged payloads as bounded parts, then the metadata root, with an exact
    /// idempotent retry path. Missing custody, conflicting slots, metadata drift, excessive
    /// metadata storage, root capacity and oversized reachability batches fail before staging.
    /// Cancellation is polled per payload and per part; a partial prefix is not completion.
    pub fn publish(
        &self,
        deployment: &mut ReferenceDeployment,
        metadata: &FileImportManifest,
        validity: CaptureInterval,
        cx: &ReplayCx,
    ) -> Result<FilePublicationReceipt, FileIngestError> {
        checkpoint(cx, STAGE_FILE_PART_PREFLIGHT)?;
        super::retained::refuse_deleted(deployment, self.import_identity)?;
        let root = self.root_manifest(metadata)?;
        self.preflight(deployment, metadata, &root, validity, None, cx)?;
        // Re-read and hash every payload before staging any publication metadata. The publisher
        // repeats custody verification at each root's commit boundary.
        for payload in &self.payloads {
            checkpoint(cx, STAGE_FILE_PART_PREFLIGHT)?;
            deployment.publisher_mut().verify_object(*payload)?;
        }
        let metadata_bytes = metadata.canonical_bytes();
        let metadata_digest = deployment.publisher_mut().stage_object(&metadata_bytes)?;
        if metadata_digest != metadata.canonical_digest() {
            return Err(ContractError::DigestMismatch.into());
        }
        deployment.publisher_mut().verify_object(metadata_digest)?;
        let mut parts = Vec::new();
        for part in &self.parts {
            checkpoint(cx, STAGE_FILE_PART_PUBLISH)?;
            parts.push(publish_one(
                deployment,
                &part.slot,
                &part.manifest,
                validity,
                cx,
            )?);
        }
        checkpoint(cx, STAGE_FILE_PART_ROOT)?;
        // Typed references do not become native children: explicitly prove all parts before the
        // aggregate can become visible. A provider acknowledgment alone never satisfies this.
        for part in &self.parts {
            verify_one(deployment, &part.slot, &part.manifest, cx)?;
        }
        let root = publish_one(deployment, &self.slot, &root, validity, cx)?;
        Ok(FilePublicationReceipt { parts, root })
    }

    /// Re-verifies the exact native and typed custody closures and their current ledger claims.
    /// A missing/retracted part, foreign root, stale descriptor, or damaged payload is refused.
    /// This read-only check does not assert that a final file-import authority batch exists.
    pub fn verify(
        &self,
        deployment: &ReferenceDeployment,
        metadata: &FileImportManifest,
        cx: &ReplayCx,
    ) -> Result<(), FileIngestError> {
        checkpoint(cx, STAGE_FILE_PART_VERIFY)?;
        super::retained::refuse_deleted(deployment, self.import_identity)?;
        let root = self.root_manifest(metadata)?;
        for part in &self.parts {
            verify_one(deployment, &part.slot, &part.manifest, cx)?;
        }
        verify_one(deployment, &self.slot, &root, cx)
    }

    /// Admit all payload and publication storage before the owning file adapter stages anything.
    /// Sizes come from its immutable, already-hashed byte slices. This read-only check grants no
    /// custody: `publish` still requires staged payloads and rehashes them before publication.
    pub(crate) fn preflight_unstaged(
        &self,
        deployment: &ReferenceDeployment,
        metadata: &FileImportManifest,
        validity: CaptureInterval,
        payload_sizes: impl IntoIterator<Item = (ContentDigest, usize)>,
        cx: &ReplayCx,
    ) -> Result<(), FileIngestError> {
        checkpoint(cx, STAGE_FILE_PART_PREFLIGHT)?;
        super::retained::refuse_deleted(deployment, self.import_identity)?;
        let mut proposed = BTreeMap::new();
        for (index, (digest, bytes)) in payload_sizes.into_iter().enumerate() {
            checkpoint(cx, STAGE_FILE_PART_PREFLIGHT)?;
            if index == MAX_FILE_PUBLICATION_PAYLOADS {
                return Err(capacity(
                    "file_publication_payloads",
                    index + 1,
                    MAX_FILE_PUBLICATION_PAYLOADS,
                ));
            }
            if proposed
                .insert(digest, bytes)
                .is_some_and(|previous| previous != bytes)
            {
                return Err(invalid("one payload identity has conflicting byte lengths"));
            }
        }
        if proposed.len() != self.payloads.len()
            || self
                .payloads
                .iter()
                .any(|digest| !proposed.contains_key(digest))
        {
            return Err(invalid(
                "proposed payload inventory differs from the publication plan",
            ));
        }
        let root = self.root_manifest(metadata)?;
        self.preflight(deployment, metadata, &root, validity, Some(&proposed), cx)
    }

    fn preflight(
        &self,
        deployment: &ReferenceDeployment,
        metadata: &FileImportManifest,
        root: &ObjectManifest,
        validity: CaptureInterval,
        proposed: Option<&BTreeMap<ContentDigest, usize>>,
        cx: &ReplayCx,
    ) -> Result<(), FileIngestError> {
        let publisher = deployment.publisher();
        let limits = publisher.limits();
        if self.child_limit > limits.max_children
            || self.child_limit > deployment.limits().batch_entries_max
        {
            return Err(invalid(
                "planned child bound exceeds the destination's admitted limits",
            ));
        }
        // This is a leaf-payload protocol. A visible payload root would be recursively expanded
        // by LocalRootPublisher and could invalidate the preflight's per-batch closure bound.
        let visible: BTreeSet<_> = publisher.visible_roots().map(|entry| entry.root).collect();
        for payload in &self.payloads {
            checkpoint(cx, STAGE_FILE_PART_PREFLIGHT)?;
            if visible.contains(payload) {
                return Err(invalid(
                    "payload is a visible root, not an opaque custody leaf",
                ));
            }
            if proposed.is_none() && publisher.spool().state(*payload).is_none() {
                return Err(invalid("planned payload has not been staged"));
            }
        }
        let mut records: Vec<(ContentDigest, usize)> = proposed
            .into_iter()
            .flat_map(|sizes| sizes.iter().map(|(digest, bytes)| (*digest, *bytes)))
            .collect();
        let metadata_bytes = metadata.canonical_bytes();
        records.push((metadata.canonical_digest(), metadata_bytes.len()));
        let mut new_roots = 0_usize;
        for (slot, manifest) in self
            .parts
            .iter()
            .map(|part| (&part.slot, &part.manifest))
            .chain(std::iter::once((&self.slot, root)))
        {
            checkpoint(cx, STAGE_FILE_PART_PREFLIGHT)?;
            if publisher.is_broken_slot(slot) {
                return Err(invalid("planned slot has a broken or indeterminate root"));
            }
            match publisher.root(slot) {
                Some(existing) if existing.root != manifest.root() => {
                    return Err(LocalPublicationError::SlotConflict {
                        slot: slot.clone(),
                        existing: existing.root,
                        requested: manifest.root(),
                    }
                    .into());
                }
                Some(existing) if existing.state != LocalPublicationState::Staged => {}
                _ => new_roots += 1,
            }
            check_ledger_claim(deployment, slot, manifest, false, Some(validity))?;
            check_record_size(deployment, slot, manifest, validity)?;
            records.push((manifest.root(), manifest.canonical_bytes().len()));
        }
        let required_roots = publisher.visible_roots().count() + new_roots;
        if required_roots > limits.max_roots {
            return Err(capacity(
                "file_publication_roots",
                required_roots,
                limits.max_roots,
            ));
        }
        let spool = publisher.spool();
        let mut seen = BTreeSet::new();
        let mut bytes = 0_u64;
        let mut objects = 0_usize;
        let object_bound = deployment
            .limits()
            .spool_object_max_bytes
            .min(limits.spool.max_object_bytes as u64);
        for (digest, length) in records {
            if length as u64 > object_bound {
                return Err(FileIngestError::SpoolCapacityExceeded {
                    limit: if proposed.is_some() {
                        "spool_object_max_bytes"
                    } else {
                        "file_publication_object_bytes"
                    },
                    required: length as u64,
                    available: object_bound,
                });
            }
            if seen.insert(digest) && spool.state(digest).is_none() {
                bytes = bytes
                    .checked_add(length as u64)
                    .ok_or_else(|| invalid("size overflow"))?;
                objects += 1;
            }
        }
        let available = limits
            .spool
            .max_total_bytes
            .saturating_sub(spool.occupied_bytes()?);
        if bytes > available {
            return Err(FileIngestError::SpoolCapacityExceeded {
                limit: if proposed.is_some() {
                    "max_total_bytes"
                } else {
                    "file_publication_total_bytes"
                },
                required: bytes,
                available,
            });
        }
        let required_objects = spool.object_count() + objects;
        if required_objects > limits.spool.max_objects {
            return Err(capacity(
                if proposed.is_some() {
                    "max_objects"
                } else {
                    "file_publication_objects"
                },
                required_objects,
                limits.spool.max_objects,
            ));
        }
        Ok(())
    }
}

fn publish_one(
    deployment: &mut ReferenceDeployment,
    slot: &SlotName,
    manifest: &ObjectManifest,
    validity: CaptureInterval,
    cx: &ReplayCx,
) -> Result<RootLedgerReceipt, FileIngestError> {
    let visible = deployment
        .publisher()
        .root(slot)
        .is_some_and(|root| root.state != LocalPublicationState::Staged);
    if !visible {
        deployment
            .publisher_mut()
            .discard_orphaned_root_temp_for(slot, manifest)?;
        deployment.publisher_mut().stage_manifest(slot, manifest)?;
    }
    Ok(deployment.publish_and_commit(slot, manifest, validity, cx)?)
}

fn check_record_size(
    deployment: &ReferenceDeployment,
    slot: &SlotName,
    manifest: &ObjectManifest,
    validity: CaptureInterval,
) -> Result<(), FileIngestError> {
    let anchor = deployment.current_anchor().clone();
    let mut batch = EvidenceDeltaBatch {
        batch_id: BatchId::parse(format!("batch:local-root:{slot}"))?,
        basis_anchor: anchor.clone(),
        new_anchor: anchor,
        deltas: vec![EvidenceDelta {
            delta_id: format!("delta:local-root:{slot}"),
            family: ROOT_REACHABILITY_FAMILY.to_owned(),
            object_id: ObjectId::parse(format!("object:local-root:{slot}"))?,
            prior_generation: None,
            new_generation: 1,
            validity,
            plane: Plane::Authority,
            payload_digest: manifest.root(),
            witness_digest: None,
            operation_id: None,
        }],
        children: manifest.children().to_vec(),
        batch_digest: ContentDigest::sha256(b""),
    };
    batch.batch_digest = batch.computed_digest();
    let encoded = fss_ledger::encode_batch(&batch)
        .map_err(|_| invalid("reachability batch cannot be encoded"))?;
    if encoded.len() as u64 > u64::from(deployment.limits().journal_record_max_bytes) {
        return Err(FileIngestError::SpoolCapacityExceeded {
            limit: "journal_record_max_bytes",
            required: encoded.len() as u64,
            available: u64::from(deployment.limits().journal_record_max_bytes),
        });
    }
    Ok(())
}

fn check_ledger_claim(
    deployment: &ReferenceDeployment,
    slot: &SlotName,
    manifest: &ObjectManifest,
    required: bool,
    validity: Option<CaptureInterval>,
) -> Result<(), FileIngestError> {
    let object = format!("object:local-root:{slot}");
    let current = deployment
        .ledger()
        .batches()
        .iter()
        .rev()
        .find_map(|batch| {
            batch
                .deltas
                .iter()
                .rev()
                .find(|delta| delta.object_id.as_str() == object)
                .map(|delta| (batch, delta))
        });
    let Some((batch, delta)) = current else {
        return if required {
            Err(invalid("part or aggregate root is not ledgered"))
        } else {
            Ok(())
        };
    };
    if delta.family != ROOT_REACHABILITY_FAMILY
        || delta.plane != Plane::Authority
        || delta.prior_generation.is_some()
        || delta.new_generation != 1
        || delta.payload_digest != manifest.root()
        || delta.witness_digest.is_some()
        || delta.operation_id.is_some()
        || validity.is_some_and(|expected| delta.validity != expected)
        || batch.batch_id.as_str() != format!("batch:local-root:{slot}")
        || batch.children.as_slice() != manifest.children()
    {
        return Err(invalid(
            "current root reachability claim differs from the exact plan",
        ));
    }
    Ok(())
}

fn verify_one(
    deployment: &ReferenceDeployment,
    slot: &SlotName,
    manifest: &ObjectManifest,
    cx: &ReplayCx,
) -> Result<(), FileIngestError> {
    checkpoint(cx, STAGE_FILE_PART_VERIFY)?;
    let publisher = deployment.publisher();
    let visible = publisher
        .root(slot)
        .ok_or_else(|| invalid("part or aggregate root is absent"))?;
    if visible.root != manifest.root() || visible.state != LocalPublicationState::Durable {
        return Err(invalid(
            "part or aggregate root is not the exact durable root",
        ));
    }
    check_ledger_claim(deployment, slot, manifest, true, None)?;
    let mut expected: BTreeSet<_> = manifest.children().iter().copied().collect();
    expected.insert(manifest.root());
    if publisher.root_closure(slot).as_ref() != Some(&expected)
        || publisher.spool().read(manifest.root())? != manifest.canonical_bytes()
    {
        return Err(invalid(
            "part or aggregate closure differs from the exact plan",
        ));
    }
    for digest in expected {
        checkpoint(cx, STAGE_FILE_PART_VERIFY)?;
        publisher.spool().require_verified(digest)?;
    }
    Ok(())
}

/// Exact v1 size, checked before encoding can allocate a second copy of hostile metadata.
fn metadata_encoded_size(metadata: &FileImportManifest) -> Result<usize, FileIngestError> {
    let mut size = 0_usize;
    let mut add = |bytes: usize| -> Result<(), FileIngestError> {
        size = size
            .checked_add(bytes)
            .ok_or_else(|| invalid("metadata size overflow"))?;
        Ok(())
    };
    for text in [
        "fss.canonical.v1",
        super::file_adapter::FILE_IMPORT_MANIFEST_SCHEMA,
        metadata.format.as_str(),
        metadata.detector_evidence.as_str(),
        metadata.adapter_id.as_str(),
        metadata.adapter_generation.as_str(),
        metadata.capture_time_label.as_str(),
    ] {
        add(8)?;
        add(text.len())?;
    }
    // Two digests, input/chunk lengths, and the five collection counts.
    add(2 * 33 + 7 * 8)?;
    add(metadata.ordered_chunks.len() * 33)?;
    add(metadata.part_roots.len() * 33)?;
    for span in &metadata.segment_spans {
        add(66)?;
        add(span.capsule_id.as_str().len())?;
    }
    for span in &metadata.omission_spans {
        add(24)?;
        add(span.reason.len())?;
    }
    for capsule in &metadata.capsule_ids {
        add(8)?;
        add(capsule.as_str().len())?;
    }
    Ok(size)
}

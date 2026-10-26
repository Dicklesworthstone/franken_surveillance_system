#![forbid(unsafe_code)]
//! Current retained historical screening at the common alert-effect boundary.
//!
//! This is a bounded metadata check, not native replay or a current-health certificate. Exact
//! capsule-linked support is joined to the diagnostic's retained import, source position and
//! original per-edge privacy generation. Reference observations without source-capsule coordinates are
//! outside this qualification; they never acquire a health claim from this check.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    CanonicalDecode, CanonicalEncode, ContentDigest, EventEvidence, EventHypothesis,
    EvidenceDeltaBatch, EvidenceEdgeRelation, ObjectId, Plane, SensorCapsule, SensorId,
};
use fss_ledger::DurableReferenceLedger;
use fss_object::ObjectManifest;
use fss_publication::{ROOT_REACHABILITY_DELTA_PREFIX, ROOT_REACHABILITY_FAMILY, SlotName};

use crate::ReferenceError;
use crate::deletion::{DeletionError, DeletionIndex, MAX_DELETION_RECORD_BYTES};
use crate::ingest::file_publication::{FilePublicationPlan, MAX_FILE_PUBLICATION_PAYLOADS};
use crate::ingest::historical_health::{
    FAMILY_HISTORICAL_HEALTH, HISTORICAL_HEALTH_OBJECT_PREFIX, HistoricalHealthError,
    HistoricalHealthRecord, read_retained_at,
};
use crate::ingest::privacy_mask::{PrivacyMaskPolicy, mask_object_id};
use crate::ingest::{FileImportManifest, RetainedReadLimits};
use crate::reference_deployment::FAMILY_PRIVACY_MASK_POLICY;

/// Maximum one metadata payload. Production readers enforce this before allocating its bytes.
pub const MAX_ALERT_HEALTH_OBJECT_BYTES: usize = 16 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 32 * 1024 * 1024;
const MAX_READS: usize = 2_048;
const MAX_DIAGNOSTICS: usize = 128;
const MAX_CAPSULES: usize = 64;
const MAX_EVENT_EDGES: usize = 4_096;
const MAX_HISTORY_WORK: usize = 16_777_216;
const MAX_MATCH_WORK: usize = 1_048_576;
const MAX_CAPSULE_BYTES: usize = 256 * 1024;

type Result<T> = std::result::Result<T, ReferenceError>;

fn refusal(reason: &'static str) -> ReferenceError {
    ReferenceError::AlertSourceHealth(reason)
}

fn charge(value: &mut usize, amount: usize, maximum: usize) -> Result<()> {
    *value = value
        .checked_add(amount)
        .filter(|value| *value <= maximum)
        .ok_or_else(|| refusal("bound_exceeded"))?;
    Ok(())
}

struct Reader<F> {
    read: F,
    reads: usize,
    bytes: usize,
    history: usize,
    comparisons: usize,
    width: usize,
    deletions: DeletionIndex,
}

impl<F, E> Reader<F>
where
    F: FnMut(ContentDigest) -> std::result::Result<Vec<u8>, E>,
    E: Into<ReferenceError>,
{
    fn read(&mut self, digest: ContentDigest, bound: usize) -> Result<Vec<u8>> {
        if self.deletions.object(digest).is_some() {
            return Err(refusal("metadata_deleted"));
        }
        charge(&mut self.reads, 1, MAX_READS)?;
        let remaining = MAX_METADATA_BYTES
            .checked_sub(self.bytes)
            .filter(|remaining| *remaining > 0)
            .ok_or_else(|| refusal("bound_exceeded"))?;
        let bytes = (self.read)(digest).map_err(|_| refusal("metadata_unavailable"))?;
        if bytes.len() > bound.min(MAX_ALERT_HEALTH_OBJECT_BYTES).min(remaining) {
            return Err(refusal("bound_exceeded"));
        }
        charge(&mut self.bytes, bytes.len(), MAX_METADATA_BYTES)?;
        if ContentDigest::sha256(&bytes) != digest {
            return Err(refusal("invalid_record"));
        }
        Ok(bytes)
    }

    fn history(&mut self, scans: usize) -> Result<()> {
        let work = self
            .width
            .checked_mul(scans)
            .ok_or_else(|| refusal("bound_exceeded"))?;
        charge(&mut self.history, work, MAX_HISTORY_WORK)
    }

    fn compare(&mut self, count: usize) -> Result<()> {
        charge(&mut self.comparisons, count, MAX_MATCH_WORK)
    }
}

fn hex(digest: ContentDigest) -> String {
    digest
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Read every applicable retained diagnostic before permitting a native alert effect.
///
/// `authority` must be the current verified deployment ledger. The callback remains the explicit
/// payload-read authority and must apply cancellation, current custody and
/// [`MAX_ALERT_HEALTH_OBJECT_BYTES`] before allocating a payload. This owner additionally shares
/// finite read-count, total-byte, history-comparison and source-matching allowances across the
/// complete operation, verifies payload hashes and current deletion authority, and brackets the
/// result with durable-head checks. It reads no native media, model or health-trace payload.
///
/// A matching finding or incomplete diagnostic refuses. A later clear diagnostic cannot erase
/// an earlier finding. No matching diagnostic, or a finite screen without findings, grants no
/// health, absence or effect authority. Uncapsuled reference-policy observations retain their
/// original eligibility checks and remain outside this source-health qualification.
///
/// Every failure uses `ReferenceError::AlertSourceHealth`; a prepared effect remains prepared
/// for explicit owner inspection/cancellation instead of inventing event-displacement evidence.
pub fn check_alert_historical_health<F, E>(
    authority: &DurableReferenceLedger,
    event: &EventHypothesis,
    read_payload: F,
) -> Result<()>
where
    F: FnMut(ContentDigest) -> std::result::Result<Vec<u8>, E>,
    E: Into<ReferenceError>,
{
    if event.evidence.len() > MAX_EVENT_EDGES {
        return Err(refusal("bound_exceeded"));
    }
    let mut supports = Vec::new();
    let mut identities = BTreeMap::new();
    for edge in &event.evidence {
        if !edge.supports || edge.relation != EvidenceEdgeRelation::Supports {
            continue;
        }
        if let Some(capsule) = edge.capsule_digest {
            let sensor = edge
                .identity_digest
                .ok_or_else(|| refusal("invalid_source_binding"))?;
            if identities
                .insert(capsule, sensor)
                .is_some_and(|prior| prior != sensor)
            {
                return Err(refusal("invalid_source_binding"));
            }
            supports.push((capsule, sensor, edge));
            if identities.len() > MAX_CAPSULES {
                return Err(refusal("bound_exceeded"));
            }
        }
    }
    if supports.is_empty() {
        return Ok(());
    }
    authority
        .verify_durable_head()
        .map_err(|_| refusal("authority_changed"))?;
    let batches = authority.batches();
    let mut width = 0;
    let mut receipts = BTreeSet::new();
    for batch in batches {
        let count = batch
            .deltas
            .len()
            .checked_add(batch.children.len())
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| refusal("bound_exceeded"))?;
        charge(&mut width, count, MAX_HISTORY_WORK)?;
        for delta in &batch.deltas {
            if delta.family == FAMILY_HISTORICAL_HEALTH
                || delta
                    .object_id
                    .as_str()
                    .starts_with(HISTORICAL_HEALTH_OBJECT_PREFIX)
            {
                if delta.family != FAMILY_HISTORICAL_HEALTH
                    || !receipts.insert(delta.payload_digest)
                {
                    return Err(refusal("invalid_record"));
                }
                if receipts.len() > MAX_DIAGNOSTICS {
                    return Err(refusal("bound_exceeded"));
                }
            }
        }
    }
    if receipts.is_empty() {
        authority
            .verify_durable_head()
            .map_err(|_| refusal("authority_changed"))?;
        return Ok(());
    }
    let mut reader = Reader {
        read: read_payload,
        reads: 0,
        bytes: 0,
        history: width,
        comparisons: 0,
        width,
        deletions: DeletionIndex::default(),
    };
    reader.history(4)?;
    let mut failure = None;
    let deletions = DeletionIndex::from_batches(batches, |digest| {
        reader
            .read(digest, MAX_DELETION_RECORD_BYTES)
            .map_err(|error| {
                failure = Some(error);
                DeletionError::RecordMismatch
            })
    });
    if let Some(error) = failure {
        return Err(error);
    }
    reader.deletions = deletions.map_err(|_| refusal("invalid_deletion_authority"))?;
    let origins = support_origins(authority, event, &supports, &mut reader)?;
    let mut capsules = BTreeMap::new();
    let mut privacy = BTreeMap::new();
    for receipt in receipts {
        // Deleted diagnostic metadata has no verifiable scope. It cannot silently erase an
        // adverse finding and re-enable a native alert; do not read the tombstoned bytes.
        if reader.deletions.object(receipt).is_some() {
            return Err(refusal("metadata_deleted"));
        }
        reader.history(8)?;
        let mut failure = None;
        let diagnostic = read_retained_at(batches, receipt, |digest, bound| {
            reader.read(digest, bound).map_err(|error| {
                failure = Some(error);
                HistoricalHealthError::Unavailable
            })
        });
        if let Some(error) = failure {
            return Err(error);
        }
        let diagnostic = diagnostic.map_err(|_| refusal("invalid_record"))?;
        let record = &diagnostic.record;
        current_root(
            authority,
            &format!("hh-{}", hex(receipt)),
            diagnostic.provenance_root,
            diagnostic.ledger_anchor.commit_sequence,
            &mut reader,
        )?;
        let sensor = ContentDigest::sha256(record.sensor_id().as_str().as_bytes());
        let mut matching = Vec::new();
        for (&(digest, identity, _), &origin) in supports.iter().zip(&origins) {
            reader.compare(1)?;
            if identity != sensor {
                continue;
            }
            let key = (record.sensor_id().clone(), origin);
            let binding = if let Some(binding) = privacy.get(&key) {
                *binding
            } else {
                let binding =
                    historical_privacy(&batches[..=origin], record.sensor_id(), &mut reader)?;
                privacy.insert(key, binding);
                binding
            };
            if binding == (record.privacy_policy_digest(), record.privacy_generation()) {
                matching.push((digest, identity));
            }
        }
        if matching.is_empty() {
            continue;
        }
        let metadata = source_metadata(authority, record, &mut reader)?;
        let first = record.first_segment();
        let end = first
            .checked_add(record.segment_count())
            .ok_or_else(|| refusal("invalid_record"))?;
        let selected = metadata
            .segment_spans
            .get(first..end)
            .ok_or_else(|| refusal("invalid_record"))?;
        for (digest, identity) in matching {
            if let std::collections::btree_map::Entry::Vacant(entry) = capsules.entry(digest) {
                let bytes = reader.read(digest, MAX_CAPSULE_BYTES)?;
                let capsule = SensorCapsule::from_canonical_bytes(&bytes)
                    .map_err(|_| refusal("invalid_source_binding"))?;
                if ContentDigest::sha256(capsule.sensor_id.as_str().as_bytes()) != identity {
                    return Err(refusal("invalid_source_binding"));
                }
                entry.insert(capsule);
            }
            let capsule = capsules
                .get(&digest)
                .ok_or_else(|| refusal("invalid_source_binding"))?;
            reader.compare(selected.len())?;
            let Some(span) = selected
                .iter()
                .find(|span| span.capsule_id == capsule.capsule_id)
            else {
                continue;
            };
            if capsule.sensor_id != *record.sensor_id()
                || capsule.stream_id != *record.stream_id()
                || capsule.source_digest != span.segment_sha256
                || capsule.source_bytes != span.len
                || capsule.gap_before != span.gap_before
            {
                return Err(refusal("invalid_source_binding"));
            }
            verify_capsule(authority, record, capsule, digest, &mut reader)?;
            if !record.summary().complete() || !record.summary().findings().is_empty() {
                return Err(refusal("support_withheld"));
            }
        }
    }
    authority
        .verify_durable_head()
        .map_err(|_| refusal("authority_changed"))?;
    Ok(())
}

// Each unchanged edge keeps the interpretation at its earliest appearance. A later review
// may carry source evidence forward but cannot reinterpret its old bytes under a new mask.
fn support_origins<F, E>(
    authority: &DurableReferenceLedger,
    event: &EventHypothesis,
    supports: &[(ContentDigest, ContentDigest, &EventEvidence)],
    reader: &mut Reader<F>,
) -> Result<Vec<usize>>
where
    F: FnMut(ContentDigest) -> std::result::Result<Vec<u8>, E>,
    E: Into<ReferenceError>,
{
    reader.history(1)?;
    let id = ObjectId::parse(format!("object:event:{}", event.event_id.as_str()))
        .map_err(|_| refusal("invalid_event_binding"))?;
    let current = authority
        .current()
        .objects
        .get(&id)
        .ok_or_else(|| refusal("invalid_event_binding"))?;
    let mut origins = vec![None; supports.len()];
    let mut generation = 0_u64;
    let mut predecessor = None;
    let mut last_root = None;
    for (index, batch) in authority.batches().iter().enumerate() {
        for delta in &batch.deltas {
            if delta.object_id != id {
                continue;
            }
            if generation >= fss_core::event::MAX_LINEAGE_DEPTH as u64 {
                return Err(refusal("bound_exceeded"));
            }
            let prior = (generation > 0).then_some(generation);
            generation = generation
                .checked_add(1)
                .ok_or_else(|| refusal("bound_exceeded"))?;
            if delta.family != "event_revision"
                || delta.plane != Plane::Authority
                || delta.prior_generation != prior
                || delta.new_generation != generation
            {
                return Err(refusal("invalid_event_binding"));
            }
            let bytes = reader.read(delta.payload_digest, MAX_ALERT_HEALTH_OBJECT_BYTES)?;
            let root = ObjectManifest::from_canonical_bytes(&bytes)
                .map_err(|_| refusal("invalid_event_binding"))?;
            if root.kind() != "event-revision" || root.root() != delta.payload_digest {
                return Err(refusal("invalid_event_binding"));
            }
            let payload = root
                .metadata_digest()
                .ok_or_else(|| refusal("invalid_event_binding"))?;
            let bytes = reader.read(payload, MAX_ALERT_HEALTH_OBJECT_BYTES)?;
            let revision = EventHypothesis::from_canonical_bytes(&bytes)
                .map_err(|_| refusal("invalid_event_binding"))?;
            if revision.event_id != event.event_id
                || revision.revision != generation
                || revision.supersedes != predecessor
                || revision.interval != delta.validity
                || delta.witness_digest != Some(revision.revision_digest())
            {
                return Err(refusal("invalid_event_binding"));
            }
            if revision.evidence.len() > MAX_EVENT_EDGES {
                return Err(refusal("bound_exceeded"));
            }
            let work = supports
                .len()
                .checked_mul(revision.evidence.len())
                .ok_or_else(|| refusal("bound_exceeded"))?;
            reader.compare(work)?;
            for ((_, _, edge), origin) in supports.iter().zip(&mut origins) {
                if origin.is_none() && revision.evidence.contains(edge) {
                    *origin = Some(index);
                }
            }
            predecessor = Some(revision.revision_digest());
            last_root = Some(delta.payload_digest);
        }
    }
    if current.family != "event_revision"
        || current.plane != Plane::Authority
        || current.generation != generation
        || event.revision != generation
        || Some(current.payload_digest) != last_root
        || predecessor != Some(event.revision_digest())
    {
        return Err(refusal("invalid_event_binding"));
    }
    origins
        .into_iter()
        .map(|origin| origin.ok_or_else(|| refusal("invalid_event_binding")))
        .collect()
}

fn historical_privacy<F, E>(
    prefix: &[EvidenceDeltaBatch],
    sensor: &SensorId,
    reader: &mut Reader<F>,
) -> Result<(Option<ContentDigest>, Option<u64>)>
where
    F: FnMut(ContentDigest) -> std::result::Result<Vec<u8>, E>,
    E: Into<ReferenceError>,
{
    reader.history(1)?;
    let id = mask_object_id(sensor).map_err(|_| refusal("invalid_privacy_binding"))?;
    let mut last = None;
    for batch in prefix {
        for delta in &batch.deltas {
            if delta.object_id != id {
                continue;
            }
            let previous = last.map(|(generation, _)| generation);
            let next = previous
                .unwrap_or(0_u64)
                .checked_add(1)
                .ok_or_else(|| refusal("invalid_privacy_binding"))?;
            if delta.family != FAMILY_PRIVACY_MASK_POLICY
                || delta.plane != Plane::Authority
                || delta.prior_generation != previous
                || delta.new_generation != next
            {
                return Err(refusal("invalid_privacy_binding"));
            }
            last = Some((delta.new_generation, delta.payload_digest));
        }
    }
    match last {
        None => Ok((None, None)),
        Some((generation, digest)) => {
            let bytes = reader.read(digest, MAX_ALERT_HEALTH_OBJECT_BYTES)?;
            let policy = PrivacyMaskPolicy::from_bytes(&bytes, digest)
                .map_err(|_| refusal("invalid_privacy_binding"))?;
            if policy.sensor_id() != sensor {
                return Err(refusal("invalid_privacy_binding"));
            }
            Ok((Some(digest), Some(generation)))
        }
    }
}

fn current_root<'a, F, E>(
    authority: &'a DurableReferenceLedger,
    name: &str,
    digest: ContentDigest,
    before: u64,
    reader: &mut Reader<F>,
) -> Result<&'a EvidenceDeltaBatch>
where
    F: FnMut(ContentDigest) -> std::result::Result<Vec<u8>, E>,
    E: Into<ReferenceError>,
{
    reader.history(1)?;
    let slot = SlotName::parse(name).map_err(|_| refusal("invalid_source_binding"))?;
    let id = fss_publication::root_reachability_object_id(&slot)
        .map_err(|_| refusal("invalid_source_binding"))?;
    let batch_id = fss_publication::root_reachability_batch_id(&slot)
        .map_err(|_| refusal("invalid_source_binding"))?;
    let batch = authority
        .batches()
        .iter()
        .find(|batch| batch.batch_id == batch_id)
        .ok_or_else(|| refusal("invalid_source_binding"))?;
    let [delta] = batch.deltas.as_slice() else {
        return Err(refusal("invalid_source_binding"));
    };
    let current = authority
        .current()
        .objects
        .get(&id)
        .ok_or_else(|| refusal("source_unavailable"))?;
    if batch.new_anchor.commit_sequence >= before
        || delta.object_id != id
        || delta.delta_id != format!("{ROOT_REACHABILITY_DELTA_PREFIX}{name}")
        || delta.family != ROOT_REACHABILITY_FAMILY
        || delta.plane != Plane::Authority
        || delta.prior_generation.is_some()
        || delta.new_generation != 1
        || delta.payload_digest != digest
        || delta.witness_digest.is_some()
        || delta.operation_id.is_some()
        || current.generation != 1
        || current.family != ROOT_REACHABILITY_FAMILY
        || current.plane != Plane::Authority
        || current.payload_digest != digest
    {
        return Err(refusal("invalid_source_binding"));
    }
    Ok(batch)
}

fn source_metadata<F, E>(
    authority: &DurableReferenceLedger,
    record: &HistoricalHealthRecord,
    reader: &mut Reader<F>,
) -> Result<FileImportManifest>
where
    F: FnMut(ContentDigest) -> std::result::Result<Vec<u8>, E>,
    E: Into<ReferenceError>,
{
    if reader.deletions.import(record.import_identity()).is_some()
        || reader.deletions.object(record.import_root()).is_some()
        || reader.deletions.object(record.trace_digest()).is_some()
    {
        return Err(refusal("source_unavailable"));
    }
    for (name, family, generation) in [
        (
            format!("object:file-import:{}", hex(record.import_identity())),
            "file_import",
            2,
        ),
        (
            format!(
                "object:file-import-manifest:{}",
                hex(record.import_identity())
            ),
            "file_import_manifest",
            1,
        ),
    ] {
        let id = ObjectId::parse(name).map_err(|_| refusal("invalid_source_binding"))?;
        let current = authority
            .current()
            .objects
            .get(&id)
            .ok_or_else(|| refusal("source_unavailable"))?;
        if current.family != family
            || current.plane != Plane::Authority
            || current.generation != generation
            || current.payload_digest != record.manifest_digest()
        {
            return Err(refusal("invalid_source_binding"));
        }
    }
    let bytes = reader.read(record.manifest_digest(), MAX_ALERT_HEALTH_OBJECT_BYTES)?;
    // These are declared metadata extents, not source-read allowances: no chunk is opened.
    // Every collection/allocation is separately bounded by the canonical manifest decoder.
    let metadata = FileImportManifest::decode_metadata(
        &bytes,
        record.manifest_digest(),
        RetainedReadLimits {
            max_source_bytes: u64::MAX,
            max_chunk_bytes: 64 * 1024 * 1024,
            max_segment_bytes: 64 * 1024 * 1024,
        },
    )
    .map_err(|_| refusal("invalid_source_binding"))?;
    let slot = format!("fi-{}", hex(record.import_identity()));
    let publication = current_root(
        authority,
        &slot,
        record.import_root(),
        record.source_anchor().commit_sequence,
        reader,
    )?;
    let root = ObjectManifest::from_canonical_bytes(
        &reader.read(record.import_root(), MAX_ALERT_HEALTH_OBJECT_BYTES)?,
    )
    .map_err(|_| refusal("invalid_source_binding"))?;
    if root.root() != record.import_root()
        || root.kind() != slot
        || root.metadata_digest() != Some(record.manifest_digest())
    {
        return Err(refusal("invalid_source_binding"));
    }
    reader.compare(
        root.children()
            .len()
            .saturating_add(publication.children.len()),
    )?;
    let root_children: BTreeSet<_> = root.children().iter().copied().collect();
    let publication_children: BTreeSet<_> = publication.children.iter().copied().collect();
    if !root_children.is_subset(&publication_children) {
        return Err(refusal("invalid_source_binding"));
    }
    let mut held = BTreeSet::new();
    let mut first_publication = publication.new_anchor.commit_sequence;
    if metadata.part_roots.is_empty() {
        held = root_children;
    } else {
        if root.children() != [record.manifest_digest()] {
            return Err(refusal("invalid_source_binding"));
        }
        let mut width = None;
        let mut prior_sequence = None;
        let mut payloads = Vec::new();
        for (index, &digest) in metadata.part_roots.iter().enumerate() {
            let name = format!("{slot}-p{index:06}");
            let proof = current_root(
                authority,
                &name,
                digest,
                publication.new_anchor.commit_sequence,
                reader,
            )?;
            if prior_sequence.is_some_and(|prior| proof.new_anchor.commit_sequence <= prior) {
                return Err(refusal("invalid_source_binding"));
            }
            prior_sequence = Some(proof.new_anchor.commit_sequence);
            first_publication = first_publication.min(proof.new_anchor.commit_sequence);
            let part = ObjectManifest::from_canonical_bytes(
                &reader.read(digest, MAX_ALERT_HEALTH_OBJECT_BYTES)?,
            )
            .map_err(|_| refusal("invalid_source_binding"))?;
            if part.kind() != name
                || part.metadata_digest().is_some()
                || part.children().is_empty()
                || part.children() != proof.children.as_slice()
                || part.root() != digest
            {
                return Err(refusal("invalid_source_binding"));
            }
            reader.compare(part.children().len())?;
            width.get_or_insert(part.children().len());
            if payloads
                .len()
                .checked_add(part.children().len())
                .is_none_or(|size| size > MAX_FILE_PUBLICATION_PAYLOADS)
            {
                return Err(refusal("bound_exceeded"));
            }
            payloads.extend_from_slice(part.children());
        }
        let plan = FilePublicationPlan::new(
            record.import_identity(),
            payloads.iter().copied(),
            width.ok_or_else(|| refusal("invalid_source_binding"))?,
        )
        .map_err(|_| refusal("invalid_source_binding"))?;
        if plan.part_roots() != metadata.part_roots
            || plan
                .root_manifest(&metadata)
                .map_err(|_| refusal("invalid_source_binding"))?
                != root
        {
            return Err(refusal("invalid_source_binding"));
        }
        held.extend(payloads);
        held.insert(record.manifest_digest());
    }
    reader.compare(
        metadata
            .ordered_chunks
            .len()
            .saturating_add(metadata.capsule_ids.len()),
    )?;
    if !metadata
        .ordered_chunks
        .iter()
        .all(|digest| held.contains(digest))
    {
        return Err(refusal("invalid_source_binding"));
    }
    // The ingest owner deduplicates before the manifest constructor admits its input count.
    // Repeated source chunks must not consume multiple custody-manifest child positions.
    let chunks: BTreeSet<_> = metadata.ordered_chunks.iter().copied().collect();
    let custody = ObjectManifest::new("custody", chunks, None)
        .map_err(|_| refusal("invalid_source_binding"))?;
    if !held.contains(&custody.root())
        || reader.read(custody.root(), MAX_ALERT_HEALTH_OBJECT_BYTES)? != custody.canonical_bytes()
    {
        return Err(refusal("invalid_source_binding"));
    }
    reader.history(1)?;
    let completion_id = format!(
        "batch:file-import:{}:manifest",
        hex(record.import_identity())
    );
    let completion = authority
        .batches()
        .iter()
        .find(|batch| batch.batch_id.as_str() == completion_id)
        .ok_or_else(|| refusal("invalid_source_binding"))?;
    reader.compare(completion.children.len())?;
    if completion
        .children
        .iter()
        .any(|digest| *digest != record.import_root() && !held.contains(digest))
    {
        return Err(refusal("invalid_source_binding"));
    }
    // Retain the exact publication membership for each subsequently selected capsule check.
    // Capsule payloads are looked up through the owning import's declared authority below.
    reader.history(1)?;
    let prefix = format!("batch:file-import:{}:c", hex(record.import_identity()));
    let mut bound = BTreeMap::new();
    let import_object = format!("object:file-import:{}", hex(record.import_identity()));
    let mut initial_custody = false;
    for batch in authority.batches() {
        if !batch
            .batch_id
            .as_str()
            .strip_prefix(&prefix)
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|byte| byte.is_ascii_digit()))
        {
            continue;
        }
        if batch.new_anchor.commit_sequence >= first_publication {
            return Err(refusal("invalid_source_binding"));
        }
        reader.compare(batch.children.len())?;
        let children: BTreeSet<_> = batch.children.iter().copied().collect();
        for delta in &batch.deltas {
            if delta.family == "file_import" && delta.object_id.as_str() == import_object {
                if initial_custody
                    || delta.plane != Plane::Authority
                    || delta.prior_generation.is_some()
                    || delta.new_generation != 1
                    || delta.payload_digest != custody.root()
                    || !children.contains(&custody.root())
                {
                    return Err(refusal("invalid_source_binding"));
                }
                initial_custody = true;
            } else if delta.family == "sensor_capsule"
                && (delta.plane != Plane::Authority
                    || delta.prior_generation.is_some()
                    || delta.new_generation != 1
                    || !held.contains(&delta.payload_digest)
                    || !children.contains(&delta.payload_digest)
                    || bound
                        .insert(delta.object_id.as_str(), delta.payload_digest)
                        .is_some())
            {
                return Err(refusal("invalid_source_binding"));
            }
        }
    }
    if !initial_custody
        || bound.len() != metadata.capsule_ids.len()
        || metadata
            .capsule_ids
            .iter()
            .any(|id| !bound.contains_key(format!("object:capsule:{}", id.as_str()).as_str()))
    {
        return Err(refusal("invalid_source_binding"));
    }
    Ok(metadata)
}

fn verify_capsule<F, E>(
    authority: &DurableReferenceLedger,
    record: &HistoricalHealthRecord,
    capsule: &SensorCapsule,
    digest: ContentDigest,
    reader: &mut Reader<F>,
) -> Result<()>
where
    F: FnMut(ContentDigest) -> std::result::Result<Vec<u8>, E>,
    E: Into<ReferenceError>,
{
    reader.history(1)?;
    let prefix = format!("batch:file-import:{}:c", hex(record.import_identity()));
    let object = format!("object:capsule:{}", capsule.capsule_id.as_str());
    let found = authority
        .batches()
        .iter()
        .filter(|batch| {
            batch
                .batch_id
                .as_str()
                .strip_prefix(&prefix)
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|byte| byte.is_ascii_digit()))
        })
        .flat_map(|batch| &batch.deltas)
        .find(|delta| delta.object_id.as_str() == object)
        .ok_or_else(|| refusal("invalid_source_binding"))?;
    let id = ObjectId::parse(&object).map_err(|_| refusal("invalid_source_binding"))?;
    let current = authority
        .current()
        .objects
        .get(&id)
        .ok_or_else(|| refusal("source_unavailable"))?;
    if found.family != "sensor_capsule"
        || found.payload_digest != digest
        || found.validity != capsule.capture
        || current.family != "sensor_capsule"
        || current.plane != Plane::Authority
        || current.generation != 1
        || current.payload_digest != digest
        || current.validity != capsule.capture
    {
        return Err(refusal("invalid_source_binding"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;

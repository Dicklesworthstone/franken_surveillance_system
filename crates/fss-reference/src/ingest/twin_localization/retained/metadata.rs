#![forbid(unsafe_code)]
//! Native metadata admission for inactive localization packages, without replay or media I/O.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CaptureInterval, EvidenceDeltaBatch, Plane, SensorId,
    StreamId,
};
use fss_publication::{
    ROOT_REACHABILITY_DELTA_PREFIX, ROOT_REACHABILITY_FAMILY, ROOT_REACHABILITY_OBJECT_PREFIX,
    root_reachability_batch_id, root_reachability_object_id,
};

use super::*;

const MAX_METADATA_OBJECTS: usize = 65_536;
const MAX_ROOT_BYTES: usize = 1024 * 1024;

/// Verified package/receipt source metadata for one inactive localization attempt.
///
/// Archive hashes are original pins. Neither archive payloads, encoded media, decoded pixels,
/// candidate geometry nor the native algorithm are read or replayed by this metadata facade.
/// A receipt may contain candidates, insufficient matches or a geometric failure; metadata
/// discovery does not turn any of these into an adopted or currently valid camera calibration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedLocalizationMetadata {
    /// Exact canonical recipe blob, also the native cold-reader lookup identity.
    pub package_identity: ContentDigest,
    /// Actual retained candidate/abstention receipt blob.
    pub receipt_digest: ContentDigest,
    /// Exact durable, currently ledgered package root.
    pub publication_root: ContentDigest,
    /// Native package publication slot.
    pub publication_slot: SlotName,
    /// Original completed recorded import.
    pub import_identity: ContentDigest,
    /// Exact source publication root.
    pub import_root: ContentDigest,
    /// Exact retained import manifest.
    pub source_manifest: ContentDigest,
    /// Original import completion anchor, not the current query head.
    pub source_anchor: LedgerAnchor,
    /// Original selected sensor capsule metadata.
    pub capsule_digest: ContentDigest,
    /// Source capsule sensor identity.
    pub sensor_id: SensorId,
    /// Source capsule stream generation identity.
    pub stream_id: StreamId,
    /// Original declared capture interval, with no clock or continuous-coverage upgrade.
    pub capture: CaptureInterval,
    /// Original coding segment selected for localization.
    pub segment_index: u64,
    /// First original segment required for native replay.
    pub range_start: u64,
    /// Complete original source range required for native replay.
    pub range_count: u64,
    /// Native recipe codec: jpeg, h264 or h265.
    pub codec: &'static str,
    /// Exact current privacy binding, checked before exposing this receipt handle.
    pub mask_binding: ContentDigest,
    /// Current immutable mask policy, or the explicit no-policy state.
    pub mask_policy: Option<ContentDigest>,
    /// Original property archive content pin; its payload is not read here.
    pub twin_digest: ContentDigest,
    /// Original authoring-scene pin; authoring input custody is not implied.
    pub scene_digest: ContentDigest,
    /// Original descriptor archive content pin; its payload is not read here.
    pub atlas_package: ContentDigest,
    /// Original atlas authoring-provenance pin, without authoring-image custody claims.
    pub atlas_provenance: ContentDigest,
    /// Original native descriptor generation pin.
    pub descriptor_generation: ContentDigest,
    /// Exact native package publication sequence.
    pub committed_sequence: u64,
}

impl RecordedLocalizationMetadata {
    /// Verify one native recipe, receipt source header and exact current publication closure.
    ///
    /// The shared retained owner reads metadata only. Opaque source/archive/pixel leaves are
    /// checked against current deletion/tombstone restrictions without requiring their bytes.
    /// Receipt geometry and decoder output are not independently interpreted or reproduced.
    /// Immutable callers must revalidate the same owner before releasing a complete response.
    pub fn read(
        source: &dyn RetainedSource,
        identity: ContentDigest,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx, "recorded_localization:metadata")?;
        if source.root() != cx.root_dir() {
            return Err(RecordedLocalizationError::InvalidRequest);
        }
        let publication_slot = slot(identity)?;
        let encoded = source
            .read_object_bounded(identity, MAX_PACKAGE_BYTES)
            .map_err(RecordedDecodeError::from)?;
        let recipe = wire::decode(&encoded)?;
        let capsule = source_binding(source, &recipe, cx)?;
        let expected = manifest(identity, &recipe)?;
        let batch = publication(source, &publication_slot, &expected)?;
        if batch.deltas[0].validity != capsule.capture
            || recipe.source_anchor.site_lineage != source.site_lineage()
            || recipe.source_anchor.commit_sequence >= batch.new_anchor.commit_sequence
        {
            return Err(RecordedLocalizationError::RetainedPackage);
        }
        let receipt = source
            .read_object_bounded(recipe.receipt, MAX_RECEIPT_BYTES)
            .map_err(RecordedDecodeError::from)?;
        let mask_policy = receipt_binding(&receipt, &recipe, &capsule)?;
        let closure = metadata_closure(source, &expected, cx)?;
        if batch.children != closure {
            return Err(RecordedLocalizationError::RetainedPackage);
        }
        checkpoint(cx, "recorded_localization:metadata_complete")?;
        let (range_start, range_count) = recipe.source.range();
        Ok(Self {
            package_identity: identity,
            receipt_digest: recipe.receipt,
            publication_root: expected.root(),
            publication_slot,
            import_identity: recipe.source.import_identity(),
            import_root: recipe.import_root,
            source_manifest: recipe.source_manifest,
            source_anchor: recipe.source_anchor,
            capsule_digest: recipe.capsule,
            sensor_id: capsule.sensor_id,
            stream_id: capsule.stream_id,
            capture: capsule.capture,
            segment_index: recipe.source.segment() as u64,
            range_start: range_start as u64,
            range_count: range_count as u64,
            codec: codec(&recipe.source),
            mask_binding: recipe.mask_binding,
            mask_policy,
            twin_digest: sha(recipe.twin),
            scene_digest: sha(recipe.scene),
            atlas_package: sha(recipe.atlas.package),
            atlas_provenance: sha(recipe.atlas.provenance),
            descriptor_generation: sha(recipe.atlas.descriptor),
            committed_sequence: batch.new_anchor.commit_sequence,
        })
    }
}

fn codec(source: &RecordedLocalizationSource) -> &'static str {
    match source {
        RecordedLocalizationSource::Jpeg(_) => "jpeg",
        RecordedLocalizationSource::H264 { .. } => "h264",
        RecordedLocalizationSource::H265 { .. } => "h265",
    }
}

/// The source-binding prefix belongs to this native owner. Do not infer geometry from the
/// opaque remaining candidate receipt: exact reproduction belongs to verify_by_replay.
pub(super) fn receipt_binding(
    bytes: &[u8],
    recipe: &Recipe,
    capsule: &SensorCapsule,
) -> Result<Option<ContentDigest>> {
    let mut decoder = CanonicalDecoder::new(bytes);
    if decoder.text().map_err(RecordedDecodeError::from)? != RECEIPT_DOMAIN
        || decoder.text().map_err(RecordedDecodeError::from)?
            != "unactivated_camera_pose_candidates"
        || decoder.text().map_err(RecordedDecodeError::from)? != codec(&recipe.source)
    {
        return Err(RecordedLocalizationError::RetainedPackage);
    }
    for expected in [
        recipe.source.import_identity(),
        recipe.import_root,
        recipe.source_manifest,
        recipe.capsule,
        capsule.source_digest,
        retained_exposure(capsule)?,
    ] {
        if decoder.digest().map_err(RecordedDecodeError::from)? != expected {
            return Err(RecordedLocalizationError::RetainedPackage);
        }
    }
    let luma = decoder.digest().map_err(RecordedDecodeError::from)?;
    let native_receipt = decoder.digest().map_err(RecordedDecodeError::from)?;
    if [luma, native_receipt]
        .iter()
        .any(|digest| digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32])
        || decoder.digest().map_err(RecordedDecodeError::from)? != recipe.mask_binding
        || LedgerAnchor::decode_canonical(&mut decoder).map_err(RecordedDecodeError::from)?
            != recipe.source_anchor
    {
        return Err(RecordedLocalizationError::RetainedPackage);
    }
    let mut optional = || -> Result<Option<ContentDigest>> {
        if decoder.bool().map_err(RecordedDecodeError::from)? {
            Ok(Some(decoder.digest().map_err(RecordedDecodeError::from)?))
        } else {
            Ok(None)
        }
    };
    if optional()? != recipe.decode_root {
        return Err(RecordedLocalizationError::RetainedPackage);
    }
    let mask_policy = optional()?;
    if crate::ingest::privacy_mask::binding_digest(mask_policy) != recipe.mask_binding {
        return Err(RecordedLocalizationError::RetainedPackage);
    }
    let (start, count) = recipe.source.range();
    for expected in [recipe.source.segment() as u64, start as u64, count as u64] {
        if decoder.u64().map_err(RecordedDecodeError::from)? != expected {
            return Err(RecordedLocalizationError::RetainedPackage);
        }
    }
    let width = decoder.u32().map_err(RecordedDecodeError::from)?;
    let height = decoder.u32().map_err(RecordedDecodeError::from)?;
    if width == 0
        || height == 0
        || width > 4096
        || height > 4096
        || u64::from(width) * u64::from(height) > 4_194_304
    {
        return Err(RecordedLocalizationError::RetainedPackage);
    }
    let native_bytes = decoder.bytes().map_err(RecordedDecodeError::from)?;
    if native_bytes.len() > 16 * 1024 || ContentDigest::sha256(native_bytes) != native_receipt {
        return Err(RecordedLocalizationError::RetainedPackage);
    }
    // Normalized twin/atlas identities are not interchangeable with archive content hashes.
    // They remain opaque here because importing the archives is explicit replay work.
    for _ in 0..2 {
        let digest = decoder.digest().map_err(RecordedDecodeError::from)?;
        if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
            return Err(RecordedLocalizationError::RetainedPackage);
        }
    }
    if decoder.digest().map_err(RecordedDecodeError::from)? != sha(recipe.atlas.descriptor) {
        return Err(RecordedLocalizationError::RetainedPackage);
    }
    let mut parameters = CanonicalEncoder::new();
    super::super::receipt::mode(&mut parameters, recipe.image);
    super::super::receipt::options(&mut parameters, recipe.options);
    let parameters = parameters.finish();
    let remaining = &bytes[decoder.offset()..];
    if !remaining.starts_with(&parameters) || remaining.len() <= parameters.len() {
        return Err(RecordedLocalizationError::RetainedPackage);
    }
    Ok(mask_policy)
}

pub(super) fn publication<'a>(
    source: &'a dyn RetainedSource,
    slot: &SlotName,
    expected: &ObjectManifest,
) -> Result<&'a EvidenceDeltaBatch> {
    let object = root_reachability_object_id(slot)
        .map_err(|_| RecordedLocalizationError::RetainedPackage)?;
    let batch_id =
        root_reachability_batch_id(slot).map_err(|_| RecordedLocalizationError::RetainedPackage)?;
    let ledger = source.ledger();
    let batch = ledger
        .batches()
        .iter()
        .rev()
        .find(|batch| batch.deltas.iter().any(|delta| delta.object_id == object))
        .ok_or(RecordedLocalizationError::RetainedPackage)?;
    let [delta] = batch.deltas.as_slice() else {
        return Err(RecordedLocalizationError::RetainedPackage);
    };
    let revision = ledger
        .current()
        .objects
        .get(&object)
        .ok_or(RecordedLocalizationError::RetainedPackage)?;
    if batch.batch_id != batch_id
        || batch.batch_digest != batch.computed_digest()
        || !batch.is_canonically_ordered()
        || batch.new_anchor.site_lineage != source.site_lineage()
        || delta.delta_id != format!("{ROOT_REACHABILITY_DELTA_PREFIX}{slot}")
        || delta.family != ROOT_REACHABILITY_FAMILY
        || delta.plane != Plane::Authority
        || delta.prior_generation.is_some()
        || delta.new_generation != 1
        || delta.payload_digest != expected.root()
        || delta.witness_digest.is_some()
        || delta.operation_id.is_some()
        || revision.family != delta.family
        || revision.plane != delta.plane
        || revision.generation != delta.new_generation
        || revision.payload_digest != delta.payload_digest
        || revision.validity != delta.validity
        || expected.kind() != slot.as_str()
    {
        return Err(RecordedLocalizationError::RetainedPackage);
    }
    source
        .check_publication(slot, expected.root(), expected.children().len())
        .map_err(RecordedDecodeError::from)?;
    if source
        .read_object_bounded(expected.root(), expected.canonical_bytes().len())
        .map_err(RecordedDecodeError::from)?
        != expected.canonical_bytes()
    {
        return Err(RecordedLocalizationError::RetainedPackage);
    }
    Ok(batch)
}

/// Follow only current native publication roots. All other digests remain opaque leaves,
/// exactly as LocalRootPublisher::root_closure does; never sniff leaf bytes as manifests.
pub(super) fn metadata_closure(
    source: &dyn RetainedSource,
    expected: &ObjectManifest,
    cx: &ReplayCx,
) -> Result<Vec<ContentDigest>> {
    let ledger = source.ledger();
    if ledger.current().objects.len() > MAX_METADATA_OBJECTS
        || ledger.batches().len() > MAX_METADATA_OBJECTS
    {
        return Err(RecordedLocalizationError::InvalidRequest);
    }
    let mut roots: BTreeMap<ContentDigest, Vec<SlotName>> = BTreeMap::new();
    for (id, revision) in &ledger.current().objects {
        checkpoint(cx, "recorded_localization:metadata_closure_index")?;
        let Some(name) = id.as_str().strip_prefix(ROOT_REACHABILITY_OBJECT_PREFIX) else {
            continue;
        };
        if revision.family == ROOT_REACHABILITY_FAMILY {
            let slot =
                SlotName::parse(name).map_err(|_| RecordedLocalizationError::RetainedPackage)?;
            roots.entry(revision.payload_digest).or_default().push(slot);
        }
    }
    let mut pending: BTreeSet<_> = expected.children().iter().copied().collect();
    let mut seen = BTreeSet::from([expected.root()]);
    while let Some(digest) = pending.pop_first() {
        checkpoint(cx, "recorded_localization:metadata_closure")?;
        if !seen.insert(digest) {
            continue;
        }
        if seen.len() > MAX_METADATA_OBJECTS {
            return Err(RecordedLocalizationError::InvalidRequest);
        }
        source
            .check_object_available(digest)
            .map_err(RecordedDecodeError::from)?;
        if let Some(publications) = roots.get(&digest) {
            let bytes = source
                .read_object_bounded(digest, MAX_ROOT_BYTES)
                .map_err(RecordedDecodeError::from)?;
            let manifest =
                ObjectManifest::from_canonical_bytes(&bytes).map_err(RecordedDecodeError::from)?;
            if manifest.root() != digest || manifest.canonical_bytes() != bytes {
                return Err(RecordedLocalizationError::RetainedPackage);
            }
            for slot in publications {
                publication(source, slot, &manifest)?;
            }
            pending.extend(
                manifest
                    .children()
                    .iter()
                    .copied()
                    .filter(|child| !seen.contains(child)),
            );
            if pending.len().saturating_add(seen.len()) > MAX_METADATA_OBJECTS {
                return Err(RecordedLocalizationError::InvalidRequest);
            }
        }
    }
    seen.remove(&expected.root());
    Ok(seen.into_iter().collect())
}

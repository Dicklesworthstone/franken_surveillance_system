#![forbid(unsafe_code)]
//! Existing file-import root-last publication with complete original-transport closure.

use super::super::file_adapter::{self, FileImportManifest};
use super::super::file_publication::FilePublicationPlan;
use super::provenance::Proof;
use super::*;
use fss_core::{BatchId, CanonicalEncode, CaptureInterval, EvidenceDelta, ObjectId, Plane};
use fss_object::ObjectManifest;
use std::collections::BTreeSet;

#[allow(clippy::too_many_arguments)]
pub(super) fn publish(
    destination: &mut ReferenceDeployment,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
    proof: Proof,
    media: Vec<u8>,
    scan: ScannedSegments,
    mut payloads: BTreeMap<ContentDigest, Vec<u8>>,
) -> Result<MpegTsImportReceipt, MpegTsImportError> {
    guard(destination, cx)?;
    // Finite reservation for reconstructed chunk hashing/copying and canonical payload setup.
    let metadata_work = (scan.capsules.len() as u64 + proof.original_chunks.len() as u64)
        .checked_mul(1024)
        .ok_or(MpegTsImportError::Invalid("publication work overflow"))?;
    work.charge(media.len() as u64 + metadata_work)
        .map_err(work_error)?;
    let proof_bytes = proof.encode()?;
    let request = &proof.request;
    let extraction = &proof.receipt;
    let proof_digest = ContentDigest::sha256(&proof_bytes);
    let identity = request.identity(extraction.source_digest())?;
    let hex = hex(identity);
    super::super::retained::refuse_deleted(destination, identity)?;
    for capsule in &scan.capsules {
        let bytes = capsule.canonical_bytes();
        payloads.insert(ContentDigest::sha256(&bytes), bytes);
    }
    let chunk_bytes = request.file.limits.chunk_bytes as usize;
    let mut chunks = Vec::new();
    for bytes in media.chunks(chunk_bytes) {
        let digest = ContentDigest::sha256(bytes);
        chunks.push(digest);
        payloads.insert(digest, bytes.to_vec());
    }
    let custody = ObjectManifest::new(
        "custody",
        chunks.iter().copied().collect::<BTreeSet<_>>(),
        None,
    )
    .map_err(storage_error)?;
    payloads.insert(custody.root(), custody.canonical_bytes());
    payloads.insert(proof_digest, proof_bytes);
    let mut manifest = FileImportManifest {
        input_sha256: ContentDigest::sha256(&media),
        input_bytes: media.len() as u64,
        format: format(extraction.codec()).as_str().into(),
        detector_evidence: DETECTOR.into(),
        chunk_bytes: chunk_bytes as u64,
        ordered_chunks: chunks,
        segment_spans: scan.segment_spans,
        omission_spans: scan.omission_spans,
        capsule_ids: scan.capsules.iter().map(|c| c.capsule_id.clone()).collect(),
        limits_digest: request.digest()?,
        adapter_id: ADAPTER.into(),
        adapter_generation: format!("{}{}", GENERATION, super::hex(proof_digest)),
        part_roots: Vec::new(),
        capture_time_label: request.time_label().into(),
    };
    let publication = FilePublicationPlan::new(
        identity,
        payloads.keys().copied(),
        destination
            .limits()
            .manifest_children_max
            .min(destination.limits().batch_entries_max),
    )?;
    manifest.part_roots = publication.part_roots();
    // Coding order is not presentation order; use extrema across all capture intervals.
    let earliest = scan
        .capsules
        .iter()
        .map(|c| c.capture.earliest)
        .min()
        .ok_or(MpegTsImportError::Invalid("empty recording"))?;
    let latest = scan
        .capsules
        .iter()
        .map(|c| c.capture.latest)
        .max()
        .ok_or(MpegTsImportError::Invalid("empty recording"))?;
    let validity = CaptureInterval::new(earliest, latest)?;
    let batch = BatchId::parse(format!("batch:file-import:{hex}:manifest"))?;
    let initial = EvidenceDelta {
        delta_id: format!("delta:file-import:{hex}:init"),
        family: "file_import".into(),
        object_id: ObjectId::parse(format!("object:file-import:{hex}"))?,
        prior_generation: None,
        new_generation: 1,
        validity,
        plane: Plane::Authority,
        payload_digest: custody.root(),
        witness_digest: None,
        operation_id: None,
    };
    let mut entries = vec![(initial, custody.root())];
    for capsule in &scan.capsules {
        let digest = ContentDigest::sha256(&capsule.canonical_bytes());
        let delta = EvidenceDelta {
            delta_id: format!("delta:capsule:{}", capsule.capsule_id.as_str()),
            family: "sensor_capsule".into(),
            object_id: ObjectId::parse(format!("object:capsule:{}", capsule.capsule_id.as_str()))?,
            prior_generation: None,
            new_generation: 1,
            validity: capsule.capture,
            plane: Plane::Authority,
            payload_digest: digest,
            witness_digest: None,
            operation_id: None,
        };
        entries.push((delta, digest));
    }
    let batches = file_adapter::plan_capsule_batches(
        entries,
        request
            .file
            .limits
            .max_batch_deltas
            .min(destination.limits().batch_entries_max),
        destination.limits().journal_record_max_bytes as usize,
        destination.current_anchor(),
        &hex,
    )?;
    let root = publication.root_manifest(&manifest)?.root();
    let metadata = manifest.canonical_digest();
    let deltas = vec![
        EvidenceDelta {
            delta_id: format!("delta:file-import:{hex}:complete"),
            family: "file_import".into(),
            object_id: ObjectId::parse(format!("object:file-import:{hex}"))?,
            prior_generation: Some(1),
            new_generation: 2,
            validity,
            plane: Plane::Authority,
            payload_digest: metadata,
            witness_digest: Some(root),
            operation_id: None,
        },
        EvidenceDelta {
            delta_id: format!("delta:manifest:{hex}"),
            family: "file_import_manifest".into(),
            object_id: ObjectId::parse(format!("object:file-import-manifest:{hex}"))?,
            prior_generation: None,
            new_generation: 1,
            validity,
            plane: Plane::Authority,
            payload_digest: metadata,
            witness_digest: Some(root),
            operation_id: None,
        },
    ];
    let children = vec![metadata, root];
    guard(destination, cx)?;
    let completed =
        file_adapter::retry::preflight(destination, &batches, &batch, identity, &manifest, cx)?;
    let receipt = |reused| MpegTsImportReceipt {
        import_identity: identity,
        import_root: root,
        manifest_digest: metadata,
        segments: manifest.segment_spans.len(),
        codec: extraction.codec(),
        program: extraction.program(),
        video_pid: extraction.video_pid(),
        original_digest: extraction.source_digest(),
        original_bytes: extraction.source_bytes(),
        elementary_bytes: extraction.elementary_bytes(),
        framing: extraction.framing(),
        capture_time_label: request.time_label(),
        proof: proof_digest,
        reused,
    };
    if completed.is_some() {
        publication.verify(destination, &manifest, cx)?;
        for (digest, expected) in &payloads {
            guard(destination, cx)?;
            work.charge(expected.len() as u64).map_err(work_error)?;
            if destination
                .publisher()
                .spool()
                .read_bounded(*digest, expected.len())
                .map_err(storage_error)?
                != *expected
            {
                return Err(MpegTsImportError::Invalid("completed custody differs"));
            }
        }
        return Ok(receipt(true));
    }
    publication.preflight_unstaged(
        destination,
        &manifest,
        validity,
        payloads.iter().map(|(d, b)| (*d, b.len())),
        cx,
    )?;
    file_adapter::check_commit_admission(
        destination,
        &batch,
        &deltas,
        &children,
        &publication,
        &batches,
        cx,
    )?;
    // A published part exposes original bytes. Retry can finish a suffix but cannot repair
    // damage behind any already visible root with a new copy from the loose file.
    let root_manifest = publication.root_manifest(&manifest)?;
    let metadata_bytes = manifest.canonical_bytes();
    for (slot, part) in publication
        .parts()
        .iter()
        .map(|p| (p.slot(), p.manifest()))
        .chain(std::iter::once((publication.slot(), &root_manifest)))
    {
        if destination
            .publisher()
            .root(slot)
            .is_some_and(|r| r.state != fss_publication::LocalPublicationState::Staged)
        {
            guard(destination, cx)?;
            if destination
                .publisher()
                .spool()
                .read_bounded(part.root(), part.canonical_bytes().len())
                .map_err(storage_error)?
                != part.canonical_bytes()
            {
                return Err(MpegTsImportError::Invalid("committed root differs"));
            }
            for digest in part.children() {
                guard(destination, cx)?;
                let part_bytes = publication
                    .parts()
                    .iter()
                    .find(|p| p.manifest().root() == *digest)
                    .map(|p| p.manifest().canonical_bytes());
                let expected = if *digest == metadata {
                    metadata_bytes.as_slice()
                } else {
                    payloads
                        .get(digest)
                        .map(Vec::as_slice)
                        .or(part_bytes.as_deref())
                        .ok_or(MpegTsImportError::Invalid("committed child membership"))?
                };
                work.charge(expected.len() as u64).map_err(work_error)?;
                if destination
                    .publisher()
                    .spool()
                    .read_bounded(*digest, expected.len())
                    .map_err(storage_error)?
                    != expected
                {
                    return Err(MpegTsImportError::Invalid("committed child differs"));
                }
            }
        }
    }
    for (digest, bytes) in &payloads {
        guard(destination, cx)?;
        work.charge(bytes.len() as u64).map_err(work_error)?;
        let staged = destination
            .publisher_mut()
            .stage_object(bytes)
            .map_err(storage_error)?;
        if staged != *digest {
            return Err(MpegTsImportError::Invalid("staged identity"));
        }
        destination
            .publisher_mut()
            .verify_object(staged)
            .map_err(storage_error)?;
    }
    for planned in batches {
        guard(destination, cx)?;
        file_adapter::append_planned_batch(
            destination,
            planned.batch_id,
            planned.deltas,
            planned.children,
            cx,
        )?;
    }
    guard(destination, cx)?;
    publication.publish_guarded(destination, &manifest, validity, cx, &|current| {
        checkpoint(cx)?;
        if guard(current, cx).is_err() {
            return Err(FileIngestError::CancellationRequested {
                stage: STAGE_MPEGTS_IMPORT,
            });
        }
        Ok(())
    })?;
    guard(destination, cx)?;
    file_adapter::append_planned_batch(destination, batch, deltas, children, cx)?;
    Ok(receipt(false))
}

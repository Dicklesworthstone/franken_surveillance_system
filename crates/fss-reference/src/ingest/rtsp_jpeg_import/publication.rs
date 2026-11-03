#![forbid(unsafe_code)]
//! Existing ledgered multipart publication, with original packet closure retained root-last.

use super::provenance::{DETECTOR_EVIDENCE, Proof};
use super::replay::Reconstruction;
use super::*;
use crate::ingest::file_adapter::{self, FileImportManifest, SegmentSpan};
use crate::ingest::file_publication::FilePublicationPlan;
use fss_core::{
    BatchId, CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, EvidenceDelta, ObjectId,
    Plane, SensorCapsule, SensorSourceBytesSpec,
};
use fss_object::ObjectManifest;
use std::collections::BTreeSet;

pub(super) fn publish(
    publisher: &LocalRootPublisher,
    prefix: &DatagramPrefix,
    destination: &mut ReferenceDeployment,
    request: &JpegImportRequest,
    authority: &dyn JpegImportAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
    reads: &ReadMeter,
    proof: Proof,
    result: Reconstruction,
    mut payloads: BTreeMap<ContentDigest, Vec<u8>>,
) -> Result<JpegImportReceipt, JpegImportError> {
    let media = &result.media;
    let capture = CaptureInterval::new(TimestampNs(0), request.receive_time)?;
    let proof_bytes = proof.encode()?;
    let proof_digest = ContentDigest::sha256(&proof_bytes);
    let identity = proof.identity()?;
    let hex = hex(identity);
    crate::ingest::retained::refuse_deleted(destination, identity)?;
    let mut capsules = Vec::new();
    let mut segments = Vec::new();
    let mut offset = 0usize;
    for (index, origin) in proof.frames.iter().enumerate() {
        let end = offset
            .checked_add(origin.bytes as usize)
            .ok_or(JpegImportError::Invalid("offset"))?;
        let source = media
            .get(offset..end)
            .ok_or(JpegImportError::Invalid("media span"))?;
        let capsule = SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
            capsule_id: CapsuleId::parse(format!("capsule:{hex}:{index:06}"))?,
            sensor_id: proof.request.sensor.clone(),
            stream_id: proof.request.stream.clone(),
            sequence: index as u64,
            capture,
            receive_time: proof.request.receive_time,
            clock_basis: ClockBasis::Estimated,
            source,
            frame_count: 1,
            gap_before: origin.gap_before,
        })?;
        segments.push(SegmentSpan {
            segment_index: index,
            offset: offset as u64,
            len: origin.bytes,
            segment_sha256: origin.encoded,
            capsule_id: capsule.capsule_id.clone(),
            gap_before: origin.gap_before,
        });
        let bytes = capsule.canonical_bytes();
        payloads.insert(ContentDigest::sha256(&bytes), bytes);
        capsules.push(capsule);
        offset = end;
    }
    let mut chunks = Vec::new();
    for bytes in media.chunks(CHUNK_BYTES) {
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
        input_sha256: ContentDigest::sha256(media),
        input_bytes: media.len() as u64,
        format: "mjpeg".into(),
        detector_evidence: DETECTOR_EVIDENCE.into(),
        chunk_bytes: CHUNK_BYTES as u64,
        ordered_chunks: chunks,
        segment_spans: segments,
        omission_spans: Vec::new(),
        capsule_ids: capsules.iter().map(|c| c.capsule_id.clone()).collect(),
        limits_digest: proof.request.digest()?,
        adapter_id: ADAPTER.into(),
        adapter_generation: format!("{GENERATION}{}", hex_digest(proof_digest)),
        part_roots: Vec::new(),
        capture_time_label: "unknown".into(),
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
    let validity = CaptureInterval::new(
        capsules[0].capture.earliest,
        capsules
            .last()
            .ok_or(JpegImportError::Invalid("empty"))?
            .capture
            .latest,
    )?;
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
    for capsule in &capsules {
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
    // A fixed one-entry partition keeps exact retries independent of deployment capacity.
    let batches = file_adapter::plan_capsule_batches(
        entries,
        1,
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
    guard(authority, request, destination, cx)?;
    let completed =
        file_adapter::retry::preflight(destination, &batches, &batch, identity, &manifest, cx)?;
    let receipt = |reused| JpegImportReceipt {
        import_identity: identity,
        import_root: root,
        manifest_digest: metadata,
        frames: proof.frames.len(),
        capture_time_label: "unknown",
        ending: "pinned_prefix",
        proof: proof_digest,
        interpretation: proof.interpretation,
        source: request.pin,
        original_bytes: proof.original_bytes(),
        media_bytes: media.len() as u64,
        read_bytes_reserved: reads.used.get(),
        replay_steps: result.steps,
        accounting: result.accounting.clone(),
        terminal: result.terminal.clone(),
        reused,
    };
    if completed.is_some() {
        publication.verify(destination, &manifest, cx)?;
        for (digest, expected) in &payloads {
            guard(authority, request, destination, cx)?;
            reads.reserve(expected.len() as u64)?;
            work.charge(expected.len() as u64).map_err(source_error)?;
            if destination
                .publisher()
                .spool()
                .read_bounded(*digest, expected.len())
                .map_err(storage_error)?
                != *expected
            {
                return Err(JpegImportError::Invalid("completed custody differs"));
            }
        }
        revalidate_source(
            publisher,
            prefix,
            destination,
            request,
            authority,
            cx,
            reads,
            work,
        )?;
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
    // A resumed part already exposes its original bytes as custody. Fresh archive input may
    // complete an unstaged suffix, but must never repair damage behind a visible prior root.
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
            guard(authority, request, destination, cx)?;
            reads.reserve(part.canonical_bytes().len() as u64)?;
            if destination
                .publisher()
                .spool()
                .read_bounded(part.root(), part.canonical_bytes().len())
                .map_err(storage_error)?
                != part.canonical_bytes()
            {
                return Err(JpegImportError::Invalid("committed root differs"));
            }
            for digest in part.children() {
                guard(authority, request, destination, cx)?;
                let expected = if *digest == metadata {
                    &metadata_bytes
                } else {
                    payloads
                        .get(digest)
                        .ok_or(JpegImportError::Invalid("committed child membership"))?
                };
                reads.reserve(expected.len() as u64)?;
                work.charge(expected.len() as u64).map_err(source_error)?;
                if destination
                    .publisher()
                    .spool()
                    .read_bounded(*digest, expected.len())
                    .map_err(storage_error)?
                    != *expected
                {
                    return Err(JpegImportError::Invalid("committed child differs"));
                }
            }
        }
    }
    for (digest, bytes) in &payloads {
        guard(authority, request, destination, cx)?;
        work.charge(bytes.len() as u64).map_err(source_error)?;
        let staged = destination
            .publisher_mut()
            .stage_object(bytes)
            .map_err(storage_error)?;
        if staged != *digest {
            return Err(JpegImportError::Invalid("staged identity"));
        }
        destination
            .publisher_mut()
            .verify_object(staged)
            .map_err(storage_error)?;
    }
    for planned in batches {
        guard(authority, request, destination, cx)?;
        file_adapter::append_planned_batch(
            destination,
            planned.batch_id,
            planned.deltas,
            planned.children,
            cx,
        )?;
    }
    guard(authority, request, destination, cx)?;
    revalidate_source(
        publisher,
        prefix,
        destination,
        request,
        authority,
        cx,
        reads,
        work,
    )?;
    publication.publish_guarded(destination, &manifest, validity, cx, &|current| {
        checkpoint(cx)?;
        if !authority.permit(request, current) {
            return Err(FileIngestError::CancellationRequested {
                stage: STAGE_RTSP_JPEG_IMPORT,
            });
        }
        Ok(())
    })?;
    guard(authority, request, destination, cx)?;
    file_adapter::append_planned_batch(destination, batch, deltas, children, cx)?;
    // Completion is already durable; do not hide it behind a late optional read/cancel check.
    Ok(receipt(false))
}
fn revalidate_source(
    publisher: &LocalRootPublisher,
    prefix: &DatagramPrefix,
    destination: &ReferenceDeployment,
    request: &JpegImportRequest,
    authority: &dyn JpegImportAuthority,
    cx: &ReplayCx,
    reads: &ReadMeter,
    work: &mut WorkBudget<'_>,
) -> Result<(), JpegImportError> {
    guard(authority, request, destination, cx)?;
    reads.reserve(request.live_read_reservation())?;
    prefix
        .revalidate(
            publisher,
            &Access {
                authority,
                request,
                destination,
                cx,
            },
            work,
        )
        .map_err(source_error)?;
    Ok(())
}
fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}
fn hex_digest(digest: ContentDigest) -> String {
    hex(digest)
}

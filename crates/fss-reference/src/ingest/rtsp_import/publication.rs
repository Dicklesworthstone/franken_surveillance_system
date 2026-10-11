#![forbid(unsafe_code)]
//! Existing file-import part/root publication with exact original-packet closure and retry checks.

use super::super::file_adapter;
use super::super::file_publication::FilePublicationPlan;
use super::provenance::Proof;
use super::*;
use fss_core::{BatchId, CanonicalEncode, CaptureInterval, EvidenceDelta, ObjectId, Plane};
use fss_object::ObjectManifest;
use std::collections::BTreeSet;

fn storage_error(error: impl Into<FileIngestError>) -> RtspImportError {
    RtspImportError::Import(Box::new(error.into()))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn publish(
    destination: &mut ReferenceDeployment,
    request: &RtspImportRequest,
    authority: &dyn RtspImportAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
    proof: Proof,
    media: Vec<u8>,
    scan: ScannedSegments,
    payloads: BTreeMap<ContentDigest, Vec<u8>>,
) -> Result<RtspImportReceipt, RtspImportError> {
    let input = PublicationInput {
        identity: request.identity()?,
        limits_digest: request.digest()?,
        codec: request.codec,
        adapter: ADAPTER,
        generation: GENERATION,
        detector_evidence: "native_rtsp_recording:reconstructed_mp4:original_rtp_retained",
        capture_time_label: request.time_label(),
        frames: proof.frames(),
        proof: proof.encode()?,
    };
    publish_import(
        destination,
        cx,
        work,
        input,
        media,
        scan,
        payloads,
        &|current| guard(authority, request, current, cx),
    )
}

/// Shared root-last publisher with unchanged capsule authority, retry and complete-closure gates.
pub(super) struct PublicationInput {
    pub identity: ContentDigest,
    pub limits_digest: ContentDigest,
    pub codec: RtspImportCodec,
    pub adapter: &'static str,
    pub generation: &'static str,
    pub detector_evidence: &'static str,
    pub capture_time_label: &'static str,
    pub frames: usize,
    pub proof: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn publish_import(
    destination: &mut ReferenceDeployment,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
    input: PublicationInput,
    media: Vec<u8>,
    scan: ScannedSegments,
    mut payloads: BTreeMap<ContentDigest, Vec<u8>>,
    authorize: &dyn Fn(&ReferenceDeployment) -> Result<(), RtspImportError>,
) -> Result<RtspImportReceipt, RtspImportError> {
    let proof_bytes = input.proof;
    let proof_digest = ContentDigest::sha256(&proof_bytes);
    let identity = input.identity;
    let hex = hex(identity);
    super::super::retained::refuse_deleted(destination, identity)?;
    for capsule in &scan.capsules {
        let bytes = capsule.canonical_bytes();
        payloads.insert(ContentDigest::sha256(&bytes), bytes);
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
        input_sha256: ContentDigest::sha256(&media),
        input_bytes: media.len() as u64,
        format: input.codec.format().as_str().into(),
        detector_evidence: input.detector_evidence.into(),
        chunk_bytes: CHUNK_BYTES as u64,
        ordered_chunks: chunks,
        segment_spans: scan.segment_spans,
        omission_spans: scan.omission_spans,
        capsule_ids: scan.capsules.iter().map(|c| c.capsule_id.clone()).collect(),
        limits_digest: input.limits_digest,
        adapter_id: input.adapter.into(),
        adapter_generation: format!("{}{}", input.generation, super::hex(proof_digest)),
        part_roots: Vec::new(),
        capture_time_label: input.capture_time_label.into(),
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
        .ok_or(RtspImportError::Invalid("empty recording"))?;
    let latest = scan
        .capsules
        .iter()
        .map(|c| c.capture.latest)
        .max()
        .ok_or(RtspImportError::Invalid("empty recording"))?;
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
    authorize(destination)?;
    let completed =
        file_adapter::retry::preflight(destination, &batches, &batch, identity, &manifest, cx)?;
    let receipt = |reused| RtspImportReceipt {
        import_identity: identity,
        import_root: root,
        manifest_digest: metadata,
        frames: input.frames,
        codec: input.codec,
        capture_time_label: input.capture_time_label,
        proof: proof_digest,
        reused,
    };
    if completed.is_some() {
        publication.verify(destination, &manifest, cx)?;
        for (digest, expected) in &payloads {
            authorize(destination)?;
            work.charge(expected.len() as u64).map_err(source_error)?;
            if destination
                .publisher()
                .spool()
                .read_bounded(*digest, expected.len())
                .map_err(storage_error)?
                != *expected
            {
                return Err(RtspImportError::Invalid("completed custody differs"));
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
    // damage behind any already visible root with a new copy from the source archive.
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
            authorize(destination)?;
            if destination
                .publisher()
                .spool()
                .read_bounded(part.root(), part.canonical_bytes().len())
                .map_err(storage_error)?
                != part.canonical_bytes()
            {
                return Err(RtspImportError::Invalid("committed root differs"));
            }
            for digest in part.children() {
                authorize(destination)?;
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
                        .ok_or(RtspImportError::Invalid("committed child membership"))?
                };
                work.charge(expected.len() as u64).map_err(source_error)?;
                if destination
                    .publisher()
                    .spool()
                    .read_bounded(*digest, expected.len())
                    .map_err(storage_error)?
                    != expected
                {
                    return Err(RtspImportError::Invalid("committed child differs"));
                }
            }
        }
    }
    for (digest, bytes) in &payloads {
        authorize(destination)?;
        work.charge(bytes.len() as u64).map_err(source_error)?;
        let staged = destination
            .publisher_mut()
            .stage_object(bytes)
            .map_err(storage_error)?;
        if staged != *digest {
            return Err(RtspImportError::Invalid("staged identity"));
        }
        destination
            .publisher_mut()
            .verify_object(staged)
            .map_err(storage_error)?;
    }
    for planned in batches {
        authorize(destination)?;
        file_adapter::append_planned_batch(
            destination,
            planned.batch_id,
            planned.deltas,
            planned.children,
            cx,
        )?;
    }
    authorize(destination)?;
    publication.publish_guarded(destination, &manifest, validity, cx, &|current| {
        checkpoint(cx)?;
        if authorize(current).is_err() {
            return Err(FileIngestError::CancellationRequested {
                stage: STAGE_RTSP_IMPORT,
            });
        }
        Ok(())
    })?;
    authorize(destination)?;
    file_adapter::append_planned_batch(destination, batch, deltas, children, cx)?;
    Ok(receipt(false))
}

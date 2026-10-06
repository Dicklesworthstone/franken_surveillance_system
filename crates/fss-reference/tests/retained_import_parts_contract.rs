#![forbid(unsafe_code)]
//! Multipart retained reads over real ledger/root/spool owners. Synthetic byte custody only.

#[allow(dead_code)]
#[path = "support/import_integrity.rs"]
mod support;

use fss_core::{
    BatchId, CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, ContentDigest, EvidenceDelta,
    ObjectId, Plane, SensorCapsule, SensorId, SensorSourceBytesSpec, StreamId, TimestampNs,
};
use fss_object::ObjectManifest;
use fss_reference::ingest::file_adapter::compute_import_identity;
use fss_reference::ingest::file_publication::FilePublicationPlan;
use fss_reference::ingest::{
    ADP_FILE_GENERATION, ADP_FILE_ROW_ID, DetectedFileFormat, FileImportManifest, FileIngestError,
    RetainedFileImport, RetainedReadLimits, SegmentSpan,
};
use fss_reference::{ReferenceDeployment, ReplayCx};
use std::fs;
use support::{TestResult, cx, directory, object_file, snapshot};

const SITE: &str = "site:retained-parts";
const SOURCE: &[u8] = b"abcdefghijklmnop";

// Spool objects may be read-only. Tamper only a test-owned file, before taking the
// no-mutation snapshot; the reader must still refuse the damaged content.
fn overwrite_fixture(path: &std::path::Path, bytes: &[u8]) -> TestResult {
    let mut permissions = fs::metadata(path)?.permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions)?;
    fs::write(path, bytes)?;
    Ok(())
}

struct Fixture {
    identity: ContentDigest,
    metadata: FileImportManifest,
    plan: FilePublicationPlan,
}

fn hex(digest: ContentDigest) -> String {
    digest
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validity() -> TestResult<CaptureInterval> {
    Ok(CaptureInterval::new(TimestampNs(0), TimestampNs(1000))?)
}

fn stage(deployment: &mut ReferenceDeployment, bytes: &[u8]) -> TestResult<ContentDigest> {
    let digest = deployment.publisher_mut().stage_object(bytes)?;
    deployment.publisher_mut().verify_object(digest)?;
    Ok(digest)
}

fn fixture(
    deployment: &mut ReferenceDeployment,
    context: &ReplayCx,
    publish_before_capsules: bool,
    complete: bool,
) -> TestResult<Fixture> {
    let sensor = SensorId::parse("sensor:retained-parts")?;
    let stream = StreamId::parse("stream:retained-parts")?;
    let limits_digest = ContentDigest::sha256(b"synthetic-part-read-limits");
    let identity = compute_import_identity(
        ContentDigest::sha256(SOURCE),
        DetectedFileFormat::JpegStream,
        limits_digest,
        ADP_FILE_GENERATION,
        &sensor,
        &stream,
    );
    let hex = hex(identity);
    let mut chunks = Vec::new();
    let mut capsule_ids = Vec::new();
    let mut spans = Vec::new();
    let mut payloads = Vec::new();
    let mut capsule_deltas = Vec::new();
    for (index, bytes) in SOURCE.chunks(8).enumerate() {
        chunks.push(stage(deployment, bytes)?);
        let capsule_id = CapsuleId::parse(format!("capsule:{hex}:{index:06}"))?;
        let capsule = SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
            capsule_id: capsule_id.clone(),
            sensor_id: sensor.clone(),
            stream_id: stream.clone(),
            sequence: index as u64,
            capture: validity()?,
            receive_time: TimestampNs(2000),
            clock_basis: ClockBasis::Estimated,
            source: bytes,
            frame_count: 1,
            gap_before: false,
        })?;
        let digest = stage(deployment, &capsule.canonical_bytes())?;
        payloads.push(digest);
        capsule_deltas.push(EvidenceDelta {
            delta_id: format!("delta:capsule:{}", capsule_id.as_str()),
            family: "sensor_capsule".to_owned(),
            object_id: ObjectId::parse(format!("object:capsule:{}", capsule_id.as_str()))?,
            prior_generation: None,
            new_generation: 1,
            validity: validity()?,
            plane: Plane::Authority,
            payload_digest: digest,
            witness_digest: None,
            operation_id: None,
        });
        spans.push(SegmentSpan {
            segment_index: index,
            offset: (index * 8) as u64,
            len: 8,
            segment_sha256: ContentDigest::sha256(bytes),
            capsule_id: capsule_id.clone(),
            gap_before: false,
        });
        capsule_ids.push(capsule_id);
    }
    let custody = ObjectManifest::new("custody", chunks.iter().copied(), None)?;
    let custody_digest = stage(deployment, &custody.canonical_bytes())?;
    let mut children = payloads.clone();
    children.push(custody_digest);
    payloads.extend(chunks.iter().copied());
    payloads.push(custody_digest);
    let plan = FilePublicationPlan::new(identity, payloads, 2)?;
    assert_eq!(plan.parts().len(), 3);
    let metadata = FileImportManifest {
        input_sha256: ContentDigest::sha256(SOURCE),
        input_bytes: SOURCE.len() as u64,
        format: "mjpeg".to_owned(),
        detector_evidence: "synthetic-custody-only:no-decode-claim".to_owned(),
        chunk_bytes: 8,
        ordered_chunks: chunks,
        segment_spans: spans,
        omission_spans: Vec::new(),
        capsule_ids,
        limits_digest,
        adapter_id: ADP_FILE_ROW_ID.to_owned(),
        adapter_generation: ADP_FILE_GENERATION.to_owned(),
        part_roots: plan.part_roots(),
        capture_time_label: "unknown".to_owned(),
    };
    if publish_before_capsules {
        plan.publish(deployment, &metadata, validity()?, context)?;
    }
    let mut deltas = vec![EvidenceDelta {
        delta_id: format!("delta:file-import:{hex}:init"),
        family: "file_import".to_owned(),
        object_id: ObjectId::parse(format!("object:file-import:{hex}"))?,
        prior_generation: None,
        new_generation: 1,
        validity: validity()?,
        plane: Plane::Authority,
        payload_digest: custody_digest,
        witness_digest: None,
        operation_id: None,
    }];
    deltas.extend(capsule_deltas);
    deployment.append_batch(
        BatchId::parse(format!("batch:file-import:{hex}:c0"))?,
        deltas,
        children,
        context,
    )?;
    if !publish_before_capsules {
        plan.publish(deployment, &metadata, validity()?, context)?;
    }
    if complete {
        let digest = metadata.canonical_digest();
        let root = plan.root_manifest(&metadata)?.root();
        deployment.append_batch(
            BatchId::parse(format!("batch:file-import:{hex}:manifest"))?,
            vec![
                EvidenceDelta {
                    delta_id: format!("delta:file-import:{hex}:complete"),
                    family: "file_import".to_owned(),
                    object_id: ObjectId::parse(format!("object:file-import:{hex}"))?,
                    prior_generation: Some(1),
                    new_generation: 2,
                    validity: validity()?,
                    plane: Plane::Authority,
                    payload_digest: digest,
                    witness_digest: Some(root),
                    operation_id: None,
                },
                EvidenceDelta {
                    delta_id: format!("delta:manifest:{hex}"),
                    family: "file_import_manifest".to_owned(),
                    object_id: ObjectId::parse(format!("object:file-import-manifest:{hex}"))?,
                    prior_generation: None,
                    new_generation: 1,
                    validity: validity()?,
                    plane: Plane::Authority,
                    payload_digest: digest,
                    witness_digest: Some(root),
                    operation_id: None,
                },
            ],
            vec![digest, root],
            context,
        )?;
    }
    Ok(Fixture {
        identity,
        metadata,
        plan,
    })
}

#[test]
fn multipart_source_reopens_and_reads_exact_segments_without_the_input_path() -> TestResult {
    let dir = directory("retained-parts-good")?;
    let context = cx("retained-parts-good")?;
    let mut deployment = ReferenceDeployment::open(&dir, SITE, &context)?;
    let fixture = fixture(&mut deployment, &context, false, true)?;
    drop(deployment);
    let deployment = ReferenceDeployment::open(&dir, SITE, &context)?;
    let before = snapshot(&dir)?;
    let retained = RetainedFileImport::open(
        &deployment,
        fixture.identity,
        RetainedReadLimits::default(),
        &context,
    )?;
    assert_eq!(retained.manifest(), &fixture.metadata);
    for index in 0..2 {
        assert_eq!(
            retained.read_segment(&deployment, index, RetainedReadLimits::default(), &context)?,
            SOURCE[index * 8..(index + 1) * 8]
        );
    }
    assert_eq!(
        retained.verify_source(&deployment, RetainedReadLimits::default(), &context)?,
        ContentDigest::sha256(SOURCE)
    );
    assert_eq!(snapshot(&dir)?, before);
    Ok(())
}

#[test]
fn durable_parts_and_aggregate_are_not_import_completion() -> TestResult {
    let dir = directory("retained-parts-incomplete")?;
    let context = cx("retained-parts-incomplete")?;
    let mut deployment = ReferenceDeployment::open(&dir, SITE, &context)?;
    let fixture = fixture(&mut deployment, &context, false, false)?;
    fixture
        .plan
        .verify(&deployment, &fixture.metadata, &context)?;
    let before = snapshot(&dir)?;
    assert!(
        RetainedFileImport::open(
            &deployment,
            fixture.identity,
            RetainedReadLimits::default(),
            &context
        )
        .is_err()
    );
    assert_eq!(snapshot(&dir)?, before);
    Ok(())
}

#[test]
fn parts_published_before_capsule_authority_are_refused() -> TestResult {
    let dir = directory("retained-parts-order")?;
    let context = cx("retained-parts-order")?;
    let mut deployment = ReferenceDeployment::open(&dir, SITE, &context)?;
    let fixture = fixture(&mut deployment, &context, true, true)?;
    let before = snapshot(&dir)?;
    let error = RetainedFileImport::open(
        &deployment,
        fixture.identity,
        RetainedReadLimits::default(),
        &context,
    )
    .err()
    .ok_or("out-of-order publication admitted")?;
    assert!(error.to_string().contains("capsule authority must precede"));
    assert_eq!(snapshot(&dir)?, before);
    Ok(())
}

#[test]
fn every_corrupted_part_manifest_is_refused_without_mutation() -> TestResult {
    for ordinal in 0..3 {
        let label = format!("retained-part-damage-{ordinal}");
        let dir = directory(&label)?;
        let context = cx(&label)?;
        let mut deployment = ReferenceDeployment::open(&dir, SITE, &context)?;
        let fixture = fixture(&mut deployment, &context, false, true)?;
        let body = fixture.plan.parts()[ordinal].manifest().canonical_bytes();
        let path = object_file(&dir, &body)?;
        let mut bytes = fs::read(&path)?;
        *bytes.last_mut().ok_or("empty object")? ^= 1;
        overwrite_fixture(&path, &bytes)?;
        let before = snapshot(&dir)?;
        assert!(
            RetainedFileImport::open(
                &deployment,
                fixture.identity,
                RetainedReadLimits::default(),
                &context
            )
            .is_err()
        );
        assert_eq!(snapshot(&dir)?, before);
    }
    Ok(())
}

#[test]
fn lost_part_record_is_not_hidden_by_a_healthy_aggregate() -> TestResult {
    let dir = directory("retained-part-missing")?;
    let context = cx("retained-part-missing")?;
    let mut deployment = ReferenceDeployment::open(&dir, SITE, &context)?;
    let fixture = fixture(&mut deployment, &context, false, true)?;
    let record = deployment
        .publisher()
        .root_dir()
        .join("roots")
        .join(format!("{}.root", fixture.plan.parts()[1].slot()));
    drop(deployment);
    fs::remove_file(record)?;
    let deployment = ReferenceDeployment::open(&dir, SITE, &context)?;
    assert!(deployment.publisher().root(fixture.plan.slot()).is_some());
    let before = snapshot(&dir)?;
    assert!(
        RetainedFileImport::open(
            &deployment,
            fixture.identity,
            RetainedReadLimits::default(),
            &context
        )
        .is_err()
    );
    assert_eq!(snapshot(&dir)?, before);
    Ok(())
}

#[test]
fn metadata_resolution_does_not_read_unrequested_media_but_source_reads_verify_it() -> TestResult {
    let dir = directory("retained-part-lazy")?;
    let context = cx("retained-part-lazy")?;
    let mut deployment = ReferenceDeployment::open(&dir, SITE, &context)?;
    let fixture = fixture(&mut deployment, &context, false, true)?;
    let path = object_file(&dir, &SOURCE[8..])?;
    let mut bytes = fs::read(&path)?;
    *bytes.last_mut().ok_or("empty source object")? ^= 1;
    overwrite_fixture(&path, &bytes)?;
    let before = snapshot(&dir)?;
    let retained = RetainedFileImport::open(
        &deployment,
        fixture.identity,
        RetainedReadLimits::default(),
        &context,
    )?;
    assert_eq!(
        retained.read_segment(&deployment, 0, RetainedReadLimits::default(), &context)?,
        SOURCE[..8]
    );
    assert!(
        retained
            .read_segment(&deployment, 1, RetainedReadLimits::default(), &context)
            .is_err()
    );
    assert!(
        retained
            .verify_source(&deployment, RetainedReadLimits::default(), &context)
            .is_err()
    );
    assert_eq!(snapshot(&dir)?, before);
    Ok(())
}

#[test]
fn standalone_metadata_does_not_grant_part_custody() -> TestResult {
    let dir = directory("retained-part-unresolved")?;
    let context = cx("retained-part-unresolved")?;
    let mut deployment = ReferenceDeployment::open(&dir, SITE, &context)?;
    let fixture = fixture(&mut deployment, &context, false, true)?;
    assert!(
        fixture
            .metadata
            .validate_retained(RetainedReadLimits::default())
            .is_err()
    );
    assert!(
        FileImportManifest::from_retained_bytes(
            &fixture.metadata.canonical_bytes(),
            fixture.metadata.canonical_digest(),
            RetainedReadLimits::default()
        )
        .is_err()
    );
    RetainedFileImport::open(
        &deployment,
        fixture.identity,
        RetainedReadLimits::default(),
        &context,
    )?;
    Ok(())
}

#[test]
fn cancellation_during_part_resolution_is_read_only() -> TestResult {
    let dir = directory("retained-part-cancel")?;
    let context = cx("retained-part-cancel")?;
    let mut deployment = ReferenceDeployment::open(&dir, SITE, &context)?;
    let fixture = fixture(&mut deployment, &context, false, true)?;
    let before = snapshot(&dir)?;
    let cancelled = cx("retained-part-cancel-probe")?;
    cancelled.set_cancel_at_checkpoint_occurrence("file_retained:root_binding", 3);
    assert!(matches!(
        RetainedFileImport::open(
            &deployment,
            fixture.identity,
            RetainedReadLimits::default(),
            &cancelled
        ),
        Err(FileIngestError::CancellationRequested { .. })
    ));
    assert_eq!(snapshot(&dir)?, before);
    Ok(())
}

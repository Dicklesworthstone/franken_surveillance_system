#![forbid(unsafe_code)]
//! Completion records cannot borrow an unrelated, staged, or later-ledgered root as evidence.

#[path = "support/import_integrity.rs"]
mod support;

use std::fs;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, ObjectId, Plane, TimestampNs,
};
use fss_object::ObjectManifest;
use fss_publication::SlotName;
use fss_reference::ingest::{
    FileImportManifest, FileIngestAdapter, FileIngestError, RetainedFileImport, RetainedReadLimits,
};
use fss_reference::{ReferenceDeployment, ReplayCx};
use support::{TestResult, cx, directory, object_file, request, snapshot};

fn hex(digest: ContentDigest) -> String {
    digest
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Deliberately inconsistent authority made with the public reference fixture primitives.
/// The ordinary importer is never used to produce these contradictory completion records.
fn complete_fixture(
    deployment: &mut ReferenceDeployment,
    identity: ContentDigest,
    root: ContentDigest,
    manifest: &FileImportManifest,
    context: &ReplayCx,
) -> TestResult {
    let hex = hex(identity);
    let object_id = ObjectId::parse(format!("object:file-import:{hex}"))?;
    let validity = CaptureInterval::new(TimestampNs(0), TimestampNs(2_000_000_000))?;
    let manifest_digest = manifest.canonical_digest();
    deployment.append_batch(
        BatchId::parse(format!("batch:file-import:{hex}:c0"))?,
        vec![EvidenceDelta {
            delta_id: format!("delta:file-import:{hex}:init"),
            family: "file_import".to_owned(),
            object_id: object_id.clone(),
            prior_generation: None,
            new_generation: 1,
            validity,
            plane: Plane::Authority,
            payload_digest: manifest_digest,
            witness_digest: None,
            operation_id: None,
        }],
        vec![manifest_digest],
        context,
    )?;
    deployment.append_batch(
        BatchId::parse(format!("batch:file-import:{hex}:manifest"))?,
        vec![
            EvidenceDelta {
                delta_id: format!("delta:file-import:{hex}:complete"),
                family: "file_import".to_owned(),
                object_id,
                prior_generation: Some(1),
                new_generation: 2,
                validity,
                plane: Plane::Authority,
                payload_digest: manifest_digest,
                witness_digest: Some(root),
                operation_id: None,
            },
            EvidenceDelta {
                delta_id: format!("delta:manifest:{hex}"),
                family: "file_import_manifest".to_owned(),
                object_id: ObjectId::parse(format!("object:file-import-manifest:{hex}"))?,
                prior_generation: None,
                new_generation: 1,
                validity,
                plane: Plane::Authority,
                payload_digest: manifest_digest,
                witness_digest: Some(root),
                operation_id: None,
            },
        ],
        vec![manifest_digest, root],
        context,
    )?;
    Ok(())
}

#[test]
fn normal_partitioned_capsule_batches_reopen_with_the_same_source() -> TestResult {
    let root = directory("root-good")?;
    let context = cx("root-good")?;
    let mut deployment = ReferenceDeployment::open(&root, "site:root-good", &context)?;
    let mut input = request()?;
    input.limits.max_batch_deltas = 2;
    let receipt = FileIngestAdapter::ingest(input.clone(), &context, &mut deployment)?;
    let expected_source = fs::read(&input.path)?;
    drop(deployment);
    let deployment = ReferenceDeployment::open(&root, "site:root-good", &context)?;
    let before = snapshot(&root)?;
    let retained = RetainedFileImport::open(
        &deployment,
        receipt.import_identity,
        RetainedReadLimits::default(),
        &context,
    )?;
    assert_eq!(retained.manifest(), &receipt.manifest);
    assert_eq!(
        retained.verify_source(&deployment, RetainedReadLimits::default(), &context)?,
        ContentDigest::sha256(&expected_source),
    );
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

#[test]
fn corrupted_root_body_cannot_be_ignored_while_metadata_remains_readable() -> TestResult {
    let root = directory("root-body-damage")?;
    let context = cx("root-body-damage")?;
    let mut deployment = ReferenceDeployment::open(&root, "site:root-body-damage", &context)?;
    let receipt = FileIngestAdapter::ingest(request()?, &context, &mut deployment)?;
    let payload = deployment.publisher().spool().read(receipt.import_root)?;
    let path = object_file(&root, &payload)?;
    let mut bytes = fs::read(&path)?;
    let last = bytes.last_mut().ok_or("empty root object")?;
    *last ^= 1;
    fs::write(path, bytes)?;
    let before = snapshot(&root)?;
    assert!(
        RetainedFileImport::open(
            &deployment,
            receipt.import_identity,
            RetainedReadLimits::default(),
            &context,
        )
        .is_err()
    );
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

#[test]
fn unbound_and_substituted_metadata_are_refused() -> TestResult {
    for substituted in [false, true] {
        let label = format!("root-metadata-{substituted}");
        let root = directory(&label)?;
        let context = cx(&label)?;
        let mut deployment = ReferenceDeployment::open(&root, "site:root-metadata", &context)?;
        let receipt = FileIngestAdapter::ingest(request()?, &context, &mut deployment)?;
        let identity = ContentDigest::sha256(label.as_bytes());
        let slot = SlotName::parse(&format!("fi-{}", hex(identity)))?;
        let other = deployment.stage_payload(b"unrelated metadata")?;
        let metadata = substituted.then_some(other);
        let manifest = ObjectManifest::new(slot.as_str(), vec![receipt.manifest_digest], metadata)?;
        deployment
            .publisher_mut()
            .stage_manifest(&slot, &manifest)?;
        deployment.publish_and_commit(
            &slot,
            &manifest,
            CaptureInterval::new(TimestampNs(0), TimestampNs(2_000_000_000))?,
            &context,
        )?;
        complete_fixture(
            &mut deployment,
            identity,
            manifest.root(),
            &receipt.manifest,
            &context,
        )?;
        let before = snapshot(&root)?;
        let result = RetainedFileImport::open(
            &deployment,
            identity,
            RetainedReadLimits::default(),
            &context,
        );
        assert!(
            matches!(result, Err(FileIngestError::CorruptSegment { detail })
            if detail.contains("exact import metadata"))
        );
        assert_eq!(snapshot(&root)?, before);
    }
    Ok(())
}

#[test]
fn source_chunks_outside_the_witnessed_root_are_not_retained_evidence() -> TestResult {
    let root = directory("root-source-outside")?;
    let context = cx("root-source-outside")?;
    let mut deployment = ReferenceDeployment::open(&root, "site:root-source-outside", &context)?;
    let receipt = FileIngestAdapter::ingest(request()?, &context, &mut deployment)?;
    let identity = ContentDigest::sha256(b"source outside root");
    let slot = SlotName::parse(&format!("fi-{}", hex(identity)))?;
    let manifest = ObjectManifest::new(slot.as_str(), Vec::new(), Some(receipt.manifest_digest))?;
    deployment
        .publisher_mut()
        .stage_manifest(&slot, &manifest)?;
    deployment.publish_and_commit(
        &slot,
        &manifest,
        CaptureInterval::new(TimestampNs(0), TimestampNs(2_000_000_000))?,
        &context,
    )?;
    complete_fixture(
        &mut deployment,
        identity,
        manifest.root(),
        &receipt.manifest,
        &context,
    )?;
    let before = snapshot(&root)?;
    let result = RetainedFileImport::open(
        &deployment,
        identity,
        RetainedReadLimits::default(),
        &context,
    );
    assert!(
        matches!(result, Err(FileIngestError::CorruptSegment { detail })
        if detail.contains("source chunks are outside"))
    );
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

#[test]
fn staged_roots_and_retroactive_publication_do_not_validate_completion() -> TestResult {
    let root = directory("root-late")?;
    let context = cx("root-late")?;
    let mut deployment = ReferenceDeployment::open(&root, "site:root-late", &context)?;
    let receipt = FileIngestAdapter::ingest(request()?, &context, &mut deployment)?;
    let identity = ContentDigest::sha256(b"retroactive root publication");
    let slot = SlotName::parse(&format!("fi-{}", hex(identity)))?;
    let manifest = ObjectManifest::new(slot.as_str(), Vec::new(), Some(receipt.manifest_digest))?;
    deployment
        .publisher_mut()
        .stage_manifest(&slot, &manifest)?;
    deployment.publisher_mut().verify_object(manifest.root())?;
    complete_fixture(
        &mut deployment,
        identity,
        manifest.root(),
        &receipt.manifest,
        &context,
    )?;
    let before = snapshot(&root)?;
    let result = RetainedFileImport::open(
        &deployment,
        identity,
        RetainedReadLimits::default(),
        &context,
    );
    assert!(
        matches!(result, Err(FileIngestError::CorruptSegment { detail })
        if detail.contains("durable publication"))
    );
    assert_eq!(snapshot(&root)?, before);
    deployment.publish_and_commit(
        &slot,
        &manifest,
        CaptureInterval::new(TimestampNs(0), TimestampNs(2_000_000_000))?,
        &context,
    )?;
    let before = snapshot(&root)?;
    let result = RetainedFileImport::open(
        &deployment,
        identity,
        RetainedReadLimits::default(),
        &context,
    );
    assert!(
        matches!(result, Err(FileIngestError::CorruptSegment { detail })
        if detail.contains("must precede import completion"))
    );
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

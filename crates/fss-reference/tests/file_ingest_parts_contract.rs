#![forbid(unsafe_code)]
//! File adapter -> multipart custody -> retained reads/deletion. Generated media fixtures only.
//! Faults are in-process injection and reopen, not process death, power loss or qualification.

#[allow(dead_code)]
#[path = "support/import_integrity.rs"]
mod support;

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use fss_core::{CanonicalEncode, ContentDigest, SensorId, TimestampNs};
use fss_object::ObjectManifest;
use fss_publication::PublishCutPoint;
use fss_reference::deletion::{approval_digest, commit_deletion, plan_deletion};
use fss_reference::ingest::file_adapter::{STAGE_COMMIT_MANIFEST, STAGE_STAGE};
use fss_reference::ingest::file_publication::{STAGE_FILE_PART_PUBLISH, STAGE_FILE_PART_ROOT};
use fss_reference::ingest::{
    FileIngestAdapter, FileIngestError, FileIngestOutcome, FileIngestReceipt, FileIngestRequest,
    RetainedFileImport, RetainedReadLimits,
};
use fss_reference::{DeploymentLimits, ReferenceDeployment, ReplayCx};
use support::{TestResult, cx, directory, request, snapshot};

const SITE: &str = "site:file-ingest-parts";
const PRINCIPAL: &str = "operator:file-ingest-parts";

fn limits() -> DeploymentLimits {
    DeploymentLimits {
        manifest_children_max: 8,
        ..DeploymentLimits::standard()
    }
}

fn input() -> TestResult<FileIngestRequest> {
    let mut input = request()?;
    input.limits.chunk_bytes = 512;
    Ok(input)
}

fn open(path: &Path, context: &ReplayCx) -> TestResult<ReferenceDeployment> {
    Ok(ReferenceDeployment::open_with_limits(
        path,
        SITE,
        limits(),
        context,
    )?)
}

fn assert_all_objects_reachable(deployment: &ReferenceDeployment) -> TestResult {
    let mut reachable = BTreeSet::new();
    for root in deployment.publisher().visible_roots() {
        reachable.extend(
            deployment
                .publisher()
                .root_closure(&root.slot)
                .ok_or("visible root has no closure")?,
        );
    }
    let staged: BTreeSet<_> = deployment.publisher().spool().digests().collect();
    assert_eq!(
        staged, reachable,
        "completed import left unreferenced custody"
    );
    Ok(())
}

fn assert_source(
    deployment: &ReferenceDeployment,
    receipt: &FileIngestReceipt,
    context: &ReplayCx,
) -> TestResult {
    let source = fs::read(input()?.path)?;
    let read_limits = RetainedReadLimits::default();
    let retained =
        RetainedFileImport::open(deployment, receipt.import_identity, read_limits, context)?;
    assert_eq!(retained.manifest(), &receipt.manifest);
    assert_eq!(
        retained.verify_source(deployment, read_limits, context)?,
        ContentDigest::sha256(&source)
    );
    for span in &receipt.manifest.segment_spans {
        assert_eq!(
            retained.read_segment(deployment, span.segment_index, read_limits, context)?,
            source[span.offset as usize..(span.offset + span.len) as usize],
        );
    }
    assert!(!receipt.absence_certifiable);
    assert_all_objects_reachable(deployment)
}

fn fixture() -> TestResult<FileIngestReceipt> {
    let root = directory("parts-baseline")?;
    let context = cx("parts-baseline")?;
    let mut deployment = open(&root, &context)?;
    let receipt = FileIngestAdapter::ingest(input()?, &context, &mut deployment)?;
    assert!(receipt.manifest.part_roots.len() > 1);
    assert_source(&deployment, &receipt, &context)?;
    Ok(receipt)
}

#[test]
fn oversized_import_completes_reopens_and_retries_without_rebinding_or_writing() -> TestResult {
    let root = directory("parts-complete")?;
    let context = cx("parts-complete")?;
    let mut deployment = open(&root, &context)?;
    let receipt = FileIngestAdapter::ingest(input()?, &context, &mut deployment)?;
    assert_eq!(receipt.outcome, FileIngestOutcome::New);
    assert!(receipt.manifest.part_roots.len() > 1);
    let aggregate = ObjectManifest::from_canonical_bytes(
        &deployment.publisher().spool().read(receipt.import_root)?,
    )?;
    assert_eq!(aggregate.children(), &[receipt.manifest_digest]);
    for part in &receipt.manifest.part_roots {
        assert!(
            !aggregate.children().contains(part),
            "typed part was made a native child"
        );
    }
    assert_source(&deployment, &receipt, &context)?;
    drop(deployment);
    let mut deployment = open(&root, &context)?;
    let before = snapshot(&root)?;
    let retry = FileIngestAdapter::ingest(input()?, &context, &mut deployment)?;
    assert_eq!(retry.outcome, FileIngestOutcome::IdempotentExisting);
    assert_eq!(retry.import_root, receipt.import_root);
    assert_eq!(retry.manifest, receipt.manifest);
    assert_eq!(retry.capsules, receipt.capsules);
    assert_source(&deployment, &retry, &context)?;
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

#[test]
fn flat_import_matches_the_previous_explicit_root_construction() -> TestResult {
    let root = directory("parts-flat-golden")?;
    let context = cx("parts-flat-golden")?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &context)?;
    let receipt = FileIngestAdapter::ingest(input()?, &context, &mut deployment)?;
    assert!(receipt.manifest.part_roots.is_empty());
    let mut payloads: BTreeSet<_> = receipt.manifest.ordered_chunks.iter().copied().collect();
    let custody = ObjectManifest::new("custody", payloads.iter().copied(), None)?;
    payloads.insert(custody.root());
    for capsule in &receipt.capsules {
        payloads.insert(ContentDigest::sha256(&capsule.canonical_bytes()));
    }
    let final_batch = deployment
        .ledger()
        .batches()
        .last()
        .ok_or("missing completion")?;
    for digest in &final_batch.children {
        if *digest != receipt.import_root && *digest != receipt.manifest_digest {
            payloads.insert(*digest);
        }
    }
    let previous = ObjectManifest::new(
        receipt.root_slot.as_str(),
        payloads,
        Some(receipt.manifest_digest),
    )?;
    assert_eq!(previous.root(), receipt.import_root);
    assert_source(&deployment, &receipt, &context)
}

#[test]
fn cancellation_at_every_part_and_after_all_parts_resumes_exactly_once() -> TestResult {
    let expected = fixture()?;
    let parts = expected.manifest.part_roots.len();
    let stops = (1..=parts)
        .map(|ordinal| (STAGE_FILE_PART_PUBLISH, ordinal))
        .chain([(STAGE_FILE_PART_ROOT, 1), (STAGE_COMMIT_MANIFEST, 1)]);
    for (case, (stage, occurrence)) in stops.enumerate() {
        let label = format!("parts-cancel-{case}");
        let root = directory(&label)?;
        let context = cx(&label)?;
        let mut deployment = open(&root, &context)?;
        context.set_cancel_at_checkpoint_occurrence(stage, occurrence);
        assert!(matches!(
            FileIngestAdapter::ingest(input()?, &context, &mut deployment),
            Err(FileIngestError::CancellationRequested { .. })
        ));
        assert!(
            RetainedFileImport::open(
                &deployment,
                expected.import_identity,
                RetainedReadLimits::default(),
                &cx("parts-read")?,
            )
            .is_err(),
            "partial publication was presented as complete"
        );
        drop(deployment);
        let resumed_context = cx("parts-resume")?;
        let mut deployment = open(&root, &resumed_context)?;
        let receipt = FileIngestAdapter::ingest(input()?, &resumed_context, &mut deployment)?;
        assert_eq!(receipt.outcome, FileIngestOutcome::Resumed);
        assert_eq!(receipt.import_root, expected.import_root);
        assert_eq!(receipt.manifest, expected.manifest);
        assert_source(&deployment, &receipt, &resumed_context)?;
        let before = snapshot(&root)?;
        let second = FileIngestAdapter::ingest(input()?, &resumed_context, &mut deployment)?;
        assert_eq!(second.outcome, FileIngestOutcome::IdempotentExisting);
        assert_eq!(snapshot(&root)?, before);
        let batch_ids: BTreeSet<_> = deployment
            .ledger()
            .batches()
            .iter()
            .map(|batch| batch.batch_id.as_str())
            .collect();
        assert_eq!(batch_ids.len(), deployment.ledger().batches().len());
    }
    Ok(())
}

#[test]
fn every_publication_crash_cut_at_each_part_preserves_resumable_custody() -> TestResult {
    let expected = fixture()?;
    for ordinal in 1..=expected.manifest.part_roots.len() {
        for (case, cut) in [
            PublishCutPoint::AfterChildrenVerified,
            PublishCutPoint::AfterManifestBody,
            PublishCutPoint::AfterRootTempWrite,
            PublishCutPoint::AfterRootRename,
        ]
        .into_iter()
        .enumerate()
        {
            let label = format!("parts-crash-{ordinal}-{case}");
            let root = directory(&label)?;
            let context = cx(&label)?;
            let mut deployment = open(&root, &context)?;
            context.set_cancel_at_checkpoint_occurrence(STAGE_FILE_PART_PUBLISH, ordinal);
            assert!(FileIngestAdapter::ingest(input()?, &context, &mut deployment).is_err());
            drop(deployment);
            let context = cx("parts-crash-run")?;
            let mut deployment = open(&root, &context)?;
            deployment.publisher_mut().inject_crash_at(cut);
            let error = FileIngestAdapter::ingest(input()?, &context, &mut deployment)
                .err()
                .ok_or("injected publication crash was not reached")?;
            assert!(format!("{error:?}").contains("InjectedCrash"));
            drop(deployment);
            let context = cx("parts-crash-recover")?;
            let mut deployment = open(&root, &context)?;
            let receipt = FileIngestAdapter::ingest(input()?, &context, &mut deployment)?;
            assert_eq!(receipt.outcome, FileIngestOutcome::Resumed);
            assert_eq!(receipt.import_root, expected.import_root);
            assert_source(&deployment, &receipt, &context)?;
        }
    }
    Ok(())
}

#[test]
fn all_payload_and_publication_quotas_are_checked_before_staging() -> TestResult {
    // Measure the indivisible completion, rather than guessing a byte threshold. Capsule
    // batches are single-entry and publication parts hold at most eight payload references.
    let probe_dir = directory("parts-completion-size")?;
    let probe_cx = cx("parts-completion-size")?;
    let mut probe = open(&probe_dir, &probe_cx)?;
    let mut probe_request = input()?;
    probe_request.limits.max_batch_deltas = 1;
    FileIngestAdapter::ingest(probe_request, &probe_cx, &mut probe)?;
    let completion = probe
        .ledger()
        .batches()
        .last()
        .ok_or("missing probe completion")?;
    assert!(completion.batch_id.as_str().ends_with(":manifest"));
    let completion_size = fss_ledger::encode_batch(completion)?.len();
    let other_max = probe
        .ledger()
        .batches()
        .iter()
        .filter(|batch| batch.batch_id != completion.batch_id)
        .map(|batch| fss_ledger::encode_batch(batch).map(|bytes| bytes.len()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .ok_or("missing probe publications")?;
    assert!(
        completion_size > other_max,
        "probe completion must be largest"
    );
    let completion_bound = u32::try_from(completion_size - 1)?;
    let cases = [
        "roots",
        "objects",
        "bytes",
        "object_bytes",
        "completion_entries",
        "completion_record",
    ];
    for case in cases {
        let root = directory(&format!("parts-capacity-{case}"))?;
        let context = cx(&format!("parts-capacity-{case}"))?;
        let mut cap = limits();
        match case {
            "roots" => cap.max_roots = 1,
            "objects" => cap.spool_max_objects = 3,
            "bytes" => cap.spool_total_max_bytes = fs::metadata(input()?.path)?.len(),
            "object_bytes" => cap.spool_object_max_bytes = 1024,
            "completion_entries" => cap.batch_entries_max = 8,
            "completion_record" => cap.journal_record_max_bytes = completion_bound,
            _ => return Err("unknown quota case".into()),
        }
        let mut deployment = ReferenceDeployment::open_with_limits(&root, SITE, cap, &context)?;
        let before = snapshot(&root)?;
        let mut req = input()?;
        // Force capsule batches small enough for the record case: the indivisible completion
        // contains all lifecycle deltas, so that is the intended later admission boundary.
        if case == "completion_record" {
            req.limits.max_batch_deltas = 1;
        }
        let result = FileIngestAdapter::ingest(req, &context, &mut deployment);
        assert!(
            matches!(result, Err(FileIngestError::SpoolCapacityExceeded { .. })),
            "{case}: {result:?}"
        );
        assert_eq!(
            snapshot(&root)?,
            before,
            "{case} staged bytes before refusing capacity"
        );
    }
    Ok(())
}

#[test]
fn cancelling_before_staging_leaves_no_source_or_part_objects() -> TestResult {
    let root = directory("parts-prestage-cancel")?;
    let context = cx("parts-prestage-cancel")?;
    let mut deployment = open(&root, &context)?;
    let before = snapshot(&root)?;
    context.set_cancel_at_checkpoint_occurrence(STAGE_STAGE, 1);
    assert!(matches!(
        FileIngestAdapter::ingest(input()?, &context, &mut deployment),
        Err(FileIngestError::CancellationRequested { .. })
    ));
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

#[test]
fn multipart_retry_refuses_changed_receive_time_before_mutation() -> TestResult {
    let root = directory("parts-retry-conflict")?;
    let context = cx("parts-retry-conflict")?;
    let mut deployment = open(&root, &context)?;
    FileIngestAdapter::ingest(input()?, &context, &mut deployment)?;
    let before = snapshot(&root)?;
    assert!(matches!(
        FileIngestAdapter::ingest(
            input()?.with_receive_time(TimestampNs(3_000_000_000)),
            &context,
            &mut deployment,
        ),
        Err(FileIngestError::ImportPlanConflict { .. })
    ));
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

#[test]
fn deletion_retracts_every_part_and_retry_never_recreates_deleted_evidence() -> TestResult {
    let root = directory("parts-delete")?;
    let context = cx("parts-delete")?;
    let mut deployment = open(&root, &context)?;
    let receipt = FileIngestAdapter::ingest(input()?, &context, &mut deployment)?;
    let before = snapshot(&root)?;
    let plan = plan_deletion(&deployment, receipt.import_identity, &context)?;
    assert_eq!(snapshot(&root)?, before);
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    for part in &receipt.manifest.part_roots {
        assert!(plan.retractions.iter().any(|entry| entry.root == *part));
    }
    let digest = plan.digest()?;
    let approval = approval_digest(digest, SITE, PRINCIPAL)?;
    commit_deletion(&mut deployment, digest, approval, PRINCIPAL, &context)?;
    for part in &receipt.manifest.part_roots {
        assert!(
            !deployment
                .publisher()
                .visible_roots()
                .any(|root| root.root == *part)
        );
        assert!(deployment.publisher().spool().read(*part).is_err());
    }
    assert!(matches!(
        RetainedFileImport::open(
            &deployment,
            receipt.import_identity,
            RetainedReadLimits::default(),
            &context,
        ),
        Err(FileIngestError::EvidenceDeleted { .. })
    ));
    let before = snapshot(&root)?;
    assert!(matches!(
        FileIngestAdapter::ingest(input()?, &context, &mut deployment),
        Err(FileIngestError::EvidenceDeleted { .. })
    ));
    commit_deletion(&mut deployment, digest, approval, PRINCIPAL, &context)?;
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

#[test]
fn deleting_one_partitioned_import_preserves_another_imports_shared_source_chunks() -> TestResult {
    let root = directory("parts-delete-shared")?;
    let context = cx("parts-delete-shared")?;
    let mut deployment = open(&root, &context)?;
    let first = FileIngestAdapter::ingest(input()?, &context, &mut deployment)?;
    let mut second_input = input()?;
    second_input.sensor_id = SensorId::parse("sensor:second-part-camera")?;
    let second = FileIngestAdapter::ingest(second_input, &context, &mut deployment)?;
    assert_eq!(
        first.manifest.ordered_chunks,
        second.manifest.ordered_chunks
    );
    let plan = plan_deletion(&deployment, first.import_identity, &context)?;
    assert!(plan.blockers.is_empty());
    for digest in &second.manifest.ordered_chunks {
        assert!(!plan.deletable.iter().any(|object| object.digest == *digest));
    }
    let digest = plan.digest()?;
    commit_deletion(
        &mut deployment,
        digest,
        approval_digest(digest, SITE, PRINCIPAL)?,
        PRINCIPAL,
        &context,
    )?;
    let retained = RetainedFileImport::open(
        &deployment,
        second.import_identity,
        RetainedReadLimits::default(),
        &context,
    )?;
    assert_eq!(
        retained.verify_source(&deployment, RetainedReadLimits::default(), &context)?,
        second.input_sha256
    );
    for part in &first.manifest.part_roots {
        assert!(
            !deployment
                .publisher()
                .visible_roots()
                .any(|root| root.root == *part)
        );
    }
    Ok(())
}

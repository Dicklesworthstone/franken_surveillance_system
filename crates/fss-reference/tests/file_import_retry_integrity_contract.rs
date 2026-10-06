#![forbid(unsafe_code)]
//! Immutable retry receipts, including interrupted imports. Synthetic fixture evidence only.

#[path = "support/import_integrity.rs"]
mod support;

use std::fs;

use fss_core::{CanonicalEncode, TimestampNs};
use fss_reference::ReferenceDeployment;
use fss_reference::ingest::{CaptureHint, FileIngestAdapter, FileIngestError, FileIngestOutcome};
use support::{TestResult, cx, directory, object_file, request, snapshot};

#[test]
fn unchanged_retry_after_reopen_preserves_evidence_and_writes_nothing() -> TestResult {
    let root = directory("retry-unchanged")?;
    let context = cx("retry-unchanged")?;
    let mut deployment = ReferenceDeployment::open(&root, "site:retry-unchanged", &context)?;
    let request = request()?;
    let first = FileIngestAdapter::ingest(request.clone(), &context, &mut deployment)?;
    drop(deployment);
    let mut deployment = ReferenceDeployment::open(&root, "site:retry-unchanged", &context)?;
    let before = snapshot(&root)?;
    let retry = FileIngestAdapter::ingest(request, &context, &mut deployment)?;
    assert_eq!(retry.outcome, FileIngestOutcome::IdempotentExisting);
    assert_eq!(retry.import_identity, first.import_identity);
    assert_eq!(retry.import_root, first.import_root);
    assert_eq!(retry.manifest, first.manifest);
    assert_eq!(retry.manifest_digest, first.manifest_digest);
    assert_eq!(retry.capsules, first.capsules);
    assert_eq!(retry.acquisition, first.acquisition);
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

#[test]
fn changed_receive_time_is_a_conflict_not_a_new_receipt() -> TestResult {
    let root = directory("retry-receive")?;
    let context = cx("retry-receive")?;
    let mut deployment = ReferenceDeployment::open(&root, "site:retry-receive", &context)?;
    let request = request()?;
    FileIngestAdapter::ingest(request.clone(), &context, &mut deployment)?;
    let before = snapshot(&root)?;
    let changed = request.with_receive_time(TimestampNs(3_000_000_000));
    let result = FileIngestAdapter::ingest(changed, &context, &mut deployment);
    assert!(matches!(
        result,
        Err(FileIngestError::ImportPlanConflict { .. })
    ));
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

#[test]
fn each_changed_capture_hint_coordinate_is_refused_without_mutation() -> TestResult {
    let original = CaptureHint::new(TimestampNs(100_000_000), 1_000, 30.0)?;
    let changes = [
        None,
        Some(CaptureHint::new(TimestampNs(200_000_000), 1_000, 30.0)?),
        Some(CaptureHint::new(TimestampNs(100_000_000), 2_000, 30.0)?),
        Some(CaptureHint::new(TimestampNs(100_000_000), 1_000, 25.0)?),
    ];
    for (index, hint) in changes.into_iter().enumerate() {
        let label = format!("retry-hint-{index}");
        let root = directory(&label)?;
        let context = cx(&label)?;
        let mut deployment = ReferenceDeployment::open(&root, "site:retry-hint", &context)?;
        let request = request()?.with_capture_hint(original);
        FileIngestAdapter::ingest(request.clone(), &context, &mut deployment)?;
        let before = snapshot(&root)?;
        let mut changed = request;
        changed.capture_hint = hint;
        let result = FileIngestAdapter::ingest(changed, &context, &mut deployment);
        assert!(matches!(
            result,
            Err(FileIngestError::ImportPlanConflict { .. })
        ));
        assert_eq!(snapshot(&root)?, before);
    }
    Ok(())
}

#[test]
fn renamed_source_is_still_the_same_idempotent_import() -> TestResult {
    let root = directory("retry-path")?;
    let context = cx("retry-path")?;
    let mut deployment = ReferenceDeployment::open(&root, "site:retry-path", &context)?;
    let request = request()?;
    let first = FileIngestAdapter::ingest(request.clone(), &context, &mut deployment)?;
    let source_dir = directory("retry-path-source")?;
    let alias = source_dir.join("renamed.264");
    fs::copy(&request.path, &alias)?;
    let mut renamed = request;
    renamed.path = alias;
    let before = snapshot(&root)?;
    let retry = FileIngestAdapter::ingest(renamed, &context, &mut deployment)?;
    assert_eq!(retry.outcome, FileIngestOutcome::IdempotentExisting);
    assert_eq!(retry.import_identity, first.import_identity);
    assert_eq!(retry.capsules, first.capsules);
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

#[test]
fn corrupted_manifest_is_not_hidden_by_reconstructing_it_from_the_input() -> TestResult {
    let root = directory("retry-manifest-damage")?;
    let context = cx("retry-manifest-damage")?;
    let mut deployment = ReferenceDeployment::open(&root, "site:retry-manifest-damage", &context)?;
    let request = request()?;
    let first = FileIngestAdapter::ingest(request.clone(), &context, &mut deployment)?;
    let path = object_file(&root, &first.manifest.canonical_bytes())?;
    let mut bytes = fs::read(&path)?;
    let last = bytes.last_mut().ok_or("empty manifest object")?;
    *last ^= 1;
    fs::write(path, bytes)?;
    let before = snapshot(&root)?;
    assert!(FileIngestAdapter::ingest(request, &context, &mut deployment).is_err());
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

#[test]
fn missing_committed_capsule_is_not_repaired_by_idempotent_retry() -> TestResult {
    let root = directory("retry-missing-capsule")?;
    let context = cx("retry-missing-capsule")?;
    let mut deployment = ReferenceDeployment::open(&root, "site:retry-missing-capsule", &context)?;
    let request = request()?;
    let first = FileIngestAdapter::ingest(request.clone(), &context, &mut deployment)?;
    let capsule = first.capsules.first().ok_or("fixture has no capsules")?;
    fs::remove_file(object_file(&root, &capsule.canonical_bytes())?)?;
    let before = snapshot(&root)?;
    assert!(FileIngestAdapter::ingest(request, &context, &mut deployment).is_err());
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

#[test]
fn missing_retained_source_is_not_hidden_by_a_fresh_source_file() -> TestResult {
    let root = directory("retry-missing-source")?;
    let context = cx("retry-missing-source")?;
    let mut deployment = ReferenceDeployment::open(&root, "site:retry-missing-source", &context)?;
    let request = request()?;
    FileIngestAdapter::ingest(request.clone(), &context, &mut deployment)?;
    let source = fs::read(&request.path)?;
    fs::remove_file(object_file(&root, &source)?)?;
    let before = snapshot(&root)?;
    assert!(FileIngestAdapter::ingest(request, &context, &mut deployment).is_err());
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

#[test]
fn interrupted_retry_checks_the_committed_prefix_before_staging_new_evidence() -> TestResult {
    use fss_reference::ingest::file_adapter::STAGE_COMMIT_CAPSULES;

    for occurrence in [2, 3] {
        let label = format!("retry-prefix-{occurrence}");
        let root = directory(&label)?;
        let interrupted = cx(&label)?;
        let mut deployment = ReferenceDeployment::open(&root, "site:retry-prefix", &interrupted)?;
        let mut input = request()?;
        input.limits.max_batch_deltas = 2;
        interrupted.set_cancel_at_checkpoint_occurrence(STAGE_COMMIT_CAPSULES, occurrence);
        let result = FileIngestAdapter::ingest(input.clone(), &interrupted, &mut deployment);
        assert!(matches!(
            result,
            Err(FileIngestError::CancellationRequested { .. })
        ));
        assert_eq!(deployment.ledger().batches().len(), occurrence - 1);
        drop(deployment);

        let resumed = cx(&format!("{label}-resume"))?;
        let mut deployment = ReferenceDeployment::open(&root, "site:retry-prefix", &resumed)?;
        let before = snapshot(&root)?;
        let changed = input.clone().with_receive_time(TimestampNs(3_000_000_000));
        let result = FileIngestAdapter::ingest(changed, &resumed, &mut deployment);
        assert!(matches!(
            result,
            Err(FileIngestError::ImportPlanConflict { .. })
        ));
        assert_eq!(snapshot(&root)?, before);

        let receipt = FileIngestAdapter::ingest(input.clone(), &resumed, &mut deployment)?;
        assert_eq!(receipt.outcome, FileIngestOutcome::Resumed);
        let before = snapshot(&root)?;
        let again = FileIngestAdapter::ingest(input, &resumed, &mut deployment)?;
        assert_eq!(again.outcome, FileIngestOutcome::IdempotentExisting);
        assert_eq!(again.capsules, receipt.capsules);
        assert_eq!(snapshot(&root)?, before);
    }
    Ok(())
}

#[test]
fn cancellation_during_retry_verification_never_mutates_authority_or_custody() -> TestResult {
    let root = directory("retry-cancel")?;
    let context = cx("retry-cancel")?;
    let mut deployment = ReferenceDeployment::open(&root, "site:retry-cancel", &context)?;
    let input = request()?;
    FileIngestAdapter::ingest(input.clone(), &context, &mut deployment)?;
    let cancelled = cx("retry-cancel-probe")?;
    cancelled.set_cancel_at_checkpoint_occurrence("file_adapter:retry_preflight", 2);
    let before = snapshot(&root)?;
    let result = FileIngestAdapter::ingest(input, &cancelled, &mut deployment);
    assert!(
        matches!(result, Err(FileIngestError::CancellationRequested { stage })
        if stage == "file_adapter:retry_preflight")
    );
    assert_eq!(snapshot(&root)?, before);
    Ok(())
}

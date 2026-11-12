#![forbid(unsafe_code)]
//! Metadata replaced after verification must respect its format cap before allocation.

use super::*;
use fss_object::{CorruptionKind, SPOOL_OBJECT_HEADER_LEN, SpoolError};
use fss_reference::deletion::MAX_DELETION_RECORD_BYTES;
use fss_reference::deletion::holds::{HoldError, MAX_HOLD_RECORD_BYTES, list_holds};
use fss_reference::ingest::FileIngestError;
use fss_reference::ingest::retained::MAX_RETAINED_MANIFEST_BYTES;
use fss_reference::reference_deployment::FAMILY_SENSOR_CAPSULE;

/// Replace an already indexed envelope with a sparse payload beyond the format's ceiling.
/// Keep its named digest intact so the specific caller limit, rather than a foreign filename,
/// refuses it. No large test-side allocation or changed ledger authority is needed.
fn oversized_payload(
    f: &Fixture,
    digest: ContentDigest,
    maximum: usize,
) -> TestResult<Vec<u8>> {
    let path = f.deployment.publisher().spool().object_path(digest);
    let original = fs::read(&path)?;
    assert!(original.len() >= SPOOL_OBJECT_HEADER_LEN);
    let declared = maximum as u64 + 1;
    let mut replacement = original.clone();
    replacement[12..20].copy_from_slice(&declared.to_le_bytes());
    fs::write(&path, replacement)?;
    fs::OpenOptions::new()
        .write(true)
        .open(path)?
        .set_len(SPOOL_OBJECT_HEADER_LEN as u64 + declared)?;
    Ok(original)
}

fn restore(f: &Fixture, digest: ContentDigest, original: Vec<u8>) -> TestResult {
    fs::write(f.deployment.publisher().spool().object_path(digest), original)?;
    Ok(())
}

fn bounded(error: &SpoolError, digest: ContentDigest, maximum: usize) -> bool {
    matches!(
        error,
        SpoolError::Corrupt {
            digest: actual,
            kind: CorruptionKind::DeclaredLengthExceedsLimit {
                declared,
                maximum: admitted,
            },
        } if *actual == digest
            && *declared == maximum as u64 + 1
            && *admitted == maximum as u64
    )
}

#[test]
fn retained_manifest_read_applies_its_metadata_cap_before_decode() -> TestResult {
    let mut f = Fixture::new("metadata-manifest")?;
    let import = f.ingest("one", 40)?;
    let retained = RetainedFileImport::open(
        &f.deployment,
        import.identity,
        RetainedReadLimits::default(),
        &f.cx,
    )?;
    let digest = retained.manifest_digest();
    let before = snapshot(f.deployment.root())?;
    let original = oversized_payload(&f, digest, MAX_RETAINED_MANIFEST_BYTES)?;
    assert!(matches!(
        RetainedFileImport::open(
            &f.deployment,
            import.identity,
            RetainedReadLimits::default(),
            &f.cx,
        ),
        Err(FileIngestError::Spool(error))
            if bounded(&error, digest, MAX_RETAINED_MANIFEST_BYTES)
    ));
    assert!(matches!(
        plan_retention(&f.deployment, &request()?, &f.cx),
        Err(DeletionError::RecordMismatch)
    ));
    restore(&f, digest, original)?;
    assert_eq!(snapshot(f.deployment.root())?, before);
    f.readable(import)?;
    Ok(())
}

#[test]
fn capsule_read_is_bounded_before_retention_decodes_or_charges_it() -> TestResult {
    let mut f = Fixture::new("metadata-capsule")?;
    f.ingest("one", 40)?;
    let request = request()?;
    let expected = plan_retention(&f.deployment, &request, &f.cx)?;
    let digest = f
        .deployment
        .ledger()
        .batches()
        .iter()
        .flat_map(|batch| &batch.deltas)
        .find(|delta| delta.family == FAMILY_SENSOR_CAPSULE)
        .ok_or("capsule authority")?
        .payload_digest;
    let before = snapshot(f.deployment.root())?;
    let original = oversized_payload(&f, digest, 16_384)?;
    assert!(matches!(
        plan_retention(&f.deployment, &request, &f.cx),
        Err(DeletionError::Spool(error)) if bounded(&error, digest, 16_384)
    ));
    restore(&f, digest, original)?;
    assert_eq!(snapshot(f.deployment.root())?, before);
    assert_eq!(plan_retention(&f.deployment, &request, &f.cx)?, expected);
    Ok(())
}

#[test]
fn oversized_hold_refuses_both_listing_and_an_already_approved_cleanup() -> TestResult {
    let mut f = Fixture::new("metadata-hold")?;
    let held = f.ingest("held", 40)?;
    let free = f.ingest("free", 80)?;
    f.hold("incident", held, HoldState::Held)?;
    let request = request()?;
    let plan = plan_retention(&f.deployment, &request, &f.cx)?
        .deletion
        .ok_or("independent cleanup")?;
    assert_eq!(plan.imports, vec![free.identity]);
    let hold = list_holds(&f.deployment, &f.authority, &f.cx)?
        .into_iter()
        .next()
        .ok_or("hold")?;
    let digest = hold.digest();
    let before = snapshot(f.deployment.root())?;
    let original = oversized_payload(&f, digest, MAX_HOLD_RECORD_BYTES)?;
    assert!(matches!(
        list_holds(&f.deployment, &f.authority, &f.cx),
        Err(HoldError::Spool(error)) if bounded(&error, digest, MAX_HOLD_RECORD_BYTES)
    ));
    assert!(matches!(
        commit_retention(
            &mut f.deployment,
            &request,
            plan.digest()?,
            plan.approval_digest(PRINCIPAL)?,
            PRINCIPAL,
            &f.cx,
        ),
        Err(DeletionError::Hold(error))
            if matches!(*error, HoldError::Spool(ref cause)
                if bounded(cause, digest, MAX_HOLD_RECORD_BYTES))
    ));
    restore(&f, digest, original)?;
    assert_eq!(snapshot(f.deployment.root())?, before);
    assert_eq!(
        commit_retention(
            &mut f.deployment,
            &request,
            plan.digest()?,
            plan.approval_digest(PRINCIPAL)?,
            PRINCIPAL,
            &f.cx,
        )?
        .outcome,
        CommitOutcome::Completed,
    );
    f.readable(held)?;
    Ok(())
}

#[test]
fn oversized_deletion_plan_or_completion_refuses_index_and_retry_without_writes() -> TestResult {
    let mut f = Fixture::new("metadata-deletion")?;
    f.ingest("one", 40)?;
    let request = request()?;
    let plan = plan_retention(&f.deployment, &request, &f.cx)?
        .deletion
        .ok_or("cleanup")?;
    let receipt = commit_retention(
        &mut f.deployment,
        &request,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &f.cx,
    )?;
    assert_eq!(receipt.outcome, CommitOutcome::Completed);
    let before = snapshot(f.deployment.root())?;
    for digest in [receipt.plan_digest, receipt.completion_digest] {
        let original = oversized_payload(&f, digest, MAX_DELETION_RECORD_BYTES)?;
        assert!(matches!(
            DeletionIndex::read(&f.deployment),
            Err(DeletionError::Spool(error))
                if bounded(&error, digest, MAX_DELETION_RECORD_BYTES)
        ));
        assert!(matches!(
            commit_retention(
                &mut f.deployment,
                &request,
                plan.digest()?,
                plan.approval_digest(PRINCIPAL)?,
                PRINCIPAL,
                &f.cx,
            ),
            Err(DeletionError::Spool(error))
                if bounded(&error, digest, MAX_DELETION_RECORD_BYTES)
        ));
        restore(&f, digest, original)?;
        assert_eq!(snapshot(f.deployment.root())?, before);
        let retry = commit_retention(
            &mut f.deployment,
            &request,
            plan.digest()?,
            plan.approval_digest(PRINCIPAL)?,
            PRINCIPAL,
            &f.cx,
        )?;
        assert_eq!(retry.outcome, CommitOutcome::AlreadyComplete);
        assert_eq!(retry.plan_digest, receipt.plan_digest);
        assert_eq!(retry.completion_digest, receipt.completion_digest);
        assert_eq!(retry.completion, receipt.completion);
        assert_eq!(snapshot(f.deployment.root())?, before);
    }
    Ok(())
}

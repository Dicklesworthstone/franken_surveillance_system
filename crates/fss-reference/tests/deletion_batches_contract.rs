#![forbid(unsafe_code)]
//! Whole-closure deletion across bounded ledger batches. Synthetic media; real local owners.
//! Injected cancellation/journal cuts are not process-death or power-loss qualification.

mod file_import_fault_support;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use file_import_fault_support::{TestResult, cx, fixture, fresh_dir, open, request, standard};
use fss_core::{ContentDigest, SensorId};
use fss_reference::deletion::{
    CommitOutcome, DeletionError, DeletionIndex, DeletionPlan, DeletionScope,
    STAGE_DELETION_AUTHORITY_BATCH_APPENDED, STAGE_DELETION_OBJECT_REMOVED,
    STAGE_DELETION_RECORD_APPENDED, STAGE_DELETION_ROOT_RETRACTED,
    commit_deletion, plan_deletion, plan_scope_deletion,
};
use fss_reference::ingest::{FileIngestError, RetainedFileImport, RetainedReadLimits};
use fss_reference::{
    AppendPhase, DeploymentLimits, FileIngestAdapter, FileIngestRequest, IncompleteTailPolicy,
    ReferenceDeployment,
};

const PRINCIPAL: &str = "operator:bounded-deletion";
const ENTRY_LIMIT: usize = 16;

type TestValue<T> = Result<T, Box<dyn std::error::Error>>;

fn setup(label: &str, frames: usize) -> TestValue<(PathBuf, DeploymentLimits, FileIngestRequest)> {
    let dir = fresh_dir(&format!("deletion-batches-{label}"))?;
    let frame = fs::read(fixture("jpeg/gray_16x16_flat.jpg")?)?;
    let path = dir.join("source.mjpeg");
    fs::write(&path, frame.repeat(frames))?;
    let limits = DeploymentLimits {
        batch_entries_max: ENTRY_LIMIT,
        manifest_children_max: 8,
        ..standard()
    };
    Ok((dir.join("deployment"), limits, request(&path, frame.len() as u64, 8)?))
}

fn prepare(
    dir: &Path,
    limits: DeploymentLimits,
    input: &FileIngestRequest,
) -> TestValue<(ReferenceDeployment, ContentDigest, DeletionPlan)> {
    let context = cx("deletion-batches-prepare")?;
    let mut deployment = open(dir, limits)?;
    let receipt = FileIngestAdapter::ingest(input.clone(), &context, &mut deployment)?;
    let plan = plan_deletion(&deployment, receipt.import_identity, &context)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    Ok((deployment, receipt.import_identity, plan))
}

fn assert_no_unlinks(deployment: &ReferenceDeployment, plan: &DeletionPlan) -> TestResult {
    for object in &plan.deletable {
        assert!(deployment.publisher().object_name_present(object.digest));
    }
    for retraction in &plan.retractions {
        let slot = fss_publication::SlotName::parse(&retraction.slot)?;
        assert_eq!(deployment.publisher().root(&slot).map(|root| root.root), Some(retraction.root));
    }
    Ok(())
}

fn assert_bounded_complete(deployment: &ReferenceDeployment, plan: &DeletionPlan) -> TestResult {
    let digest = plan.digest()?;
    let prefix = DeletionPlan::record_batch_id(digest);
    let batches: Vec<_> = deployment.ledger().batches().iter()
        .filter(|batch| batch.batch_id.as_str().starts_with(&prefix)).collect();
    let ids: BTreeSet<_> = batches.iter().map(|batch| &batch.batch_id).collect();
    assert_eq!(ids.len(), batches.len());
    let mut tombstones = BTreeSet::new();
    let mut retractions = BTreeSet::new();
    for batch in &batches {
        assert!(batch.deltas.len() <= ENTRY_LIMIT);
        assert!(batch.children.len() <= ENTRY_LIMIT);
        assert!(fss_ledger::encode_batch(batch)?.len() <= deployment.limits().journal_record_max_bytes as usize);
        for delta in &batch.deltas {
            match delta.family.as_str() {
                "deletion_tombstone" => assert!(tombstones.insert(delta.object_id.as_str())),
                "local_root_retraction" => assert!(retractions.insert(delta.object_id.as_str())),
                _ => {}
            }
        }
    }
    assert_eq!(tombstones.len(), plan.tombstones.len());
    assert_eq!(retractions.len(), plan.retractions.len());
    assert_eq!(batches.last().map(|batch| batch.batch_id.as_str()), Some(DeletionPlan::completion_batch_id(digest).as_str()));
    let index = DeletionIndex::read(deployment)?;
    assert!(index.plan(digest).ok_or("missing deletion")?.is_complete());
    for object in &plan.deletable {
        assert!(!deployment.publisher().object_name_present(object.digest));
    }
    Ok(())
}

#[test]
fn large_multipart_import_is_deleted_without_raising_any_batch_limit() -> TestResult {
    let (dir, limits, input) = setup("complete", 64)?;
    let (mut deployment, identity, plan) = prepare(&dir, limits, &input)?;
    assert!(plan.tombstones.len() > ENTRY_LIMIT);
    assert!(plan.retractions.len() > 1);
    let digest = plan.digest()?;
    let approval = plan.approval_digest(PRINCIPAL)?;
    let context = cx("deletion-batches-complete")?;
    let receipt = commit_deletion(&mut deployment, digest, approval, PRINCIPAL, &context)?;
    assert_eq!(receipt.outcome, CommitOutcome::Completed);
    assert_bounded_complete(&deployment, &plan)?;
    assert!(input.path.is_file(), "the operator's original file is not owned by deletion");
    drop(deployment);
    let mut deployment = open(&dir, limits)?;
    assert_bounded_complete(&deployment, &plan)?;
    let count = deployment.ledger().batches().len();
    assert_eq!(commit_deletion(&mut deployment, digest, approval, PRINCIPAL, &context)?.outcome, CommitOutcome::AlreadyComplete);
    assert_eq!(deployment.ledger().batches().len(), count);
    assert!(matches!(RetainedFileImport::open(&deployment, identity, RetainedReadLimits::default(), &context), Err(FileIngestError::EvidenceDeleted { .. })));
    Ok(())
}

#[test]
fn every_authority_boundary_denies_reads_but_preserves_all_bytes_until_resume() -> TestResult {
    let (dir, limits, input) = setup("count", 40)?;
    let (mut deployment, _, plan) = prepare(&dir, limits, &input)?;
    let digest = plan.digest()?;
    commit_deletion(&mut deployment, digest, plan.approval_digest(PRINCIPAL)?, PRINCIPAL, &cx("count")?)?;
    let prefix = DeletionPlan::record_batch_id(digest);
    let authority_batches = deployment.ledger().batches().iter()
        .filter(|batch| batch.batch_id.as_str() == prefix || batch.batch_id.as_str().starts_with(&format!("{prefix}:part:"))).count();
    assert!(authority_batches > 2);
    for occurrence in 1..=authority_batches {
        let (dir, limits, input) = setup(&format!("cut-{occurrence}"), 40)?;
        let (mut deployment, identity, plan) = prepare(&dir, limits, &input)?;
        let digest = plan.digest()?;
        let approval = plan.approval_digest(PRINCIPAL)?;
        let context = cx("deletion-batches-cut")?;
        context.set_cancel_at_checkpoint_occurrence(STAGE_DELETION_AUTHORITY_BATCH_APPENDED, occurrence);
        assert!(matches!(commit_deletion(&mut deployment, digest, approval, PRINCIPAL, &context), Err(DeletionError::Cancelled { stage: STAGE_DELETION_AUTHORITY_BATCH_APPENDED })));
        assert!(context.is_drain_completed());
        assert_no_unlinks(&deployment, &plan)?;
        let fresh = cx("deletion-batches-read")?;
        assert!(matches!(RetainedFileImport::open(&deployment, identity, RetainedReadLimits::default(), &fresh), Err(FileIngestError::EvidenceDeleted { .. })));
        assert!(!DeletionIndex::read(&deployment)?.plan(digest).ok_or("missing plan")?.is_complete());
        drop(deployment);
        let mut deployment = open(&dir, limits)?;
        assert_no_unlinks(&deployment, &plan)?;
        assert_eq!(commit_deletion(&mut deployment, digest, approval, PRINCIPAL, &fresh)?.outcome, CommitOutcome::Resumed);
        assert_bounded_complete(&deployment, &plan)?;
    }
    Ok(())
}

#[test]
fn torn_and_committed_authority_append_phases_resume_without_duplicate_transitions() -> TestResult {
    for phase in [AppendPhase::BodyWrite, AppendPhase::BodySync, AppendPhase::CommitWrite, AppendPhase::CommitSync] {
        let (dir, limits, input) = setup(&format!("append-{phase:?}"), 40)?;
        let (mut deployment, _, plan) = prepare(&dir, limits, &input)?;
        let digest = plan.digest()?;
        let approval = plan.approval_digest(PRINCIPAL)?;
        let stop = cx("deletion-batches-record")?;
        stop.set_cancel_at_checkpoint_occurrence(STAGE_DELETION_RECORD_APPENDED, 1);
        assert!(matches!(commit_deletion(&mut deployment, digest, approval, PRINCIPAL, &stop), Err(DeletionError::Cancelled { .. })));
        deployment.fail_ledger_append_after_phase(phase);
        let result = commit_deletion(&mut deployment, digest, approval, PRINCIPAL, &cx("deletion-batches-append")?);
        assert!(result.is_err());
        assert_no_unlinks(&deployment, &plan)?;
        deployment.ledgered_publisher().reconcile_ledger_append(IncompleteTailPolicy::Truncate)?;
        drop(deployment);
        let mut deployment = open(&dir, limits)?;
        commit_deletion(&mut deployment, digest, approval, PRINCIPAL, &cx("deletion-batches-resume")?)?;
        assert_bounded_complete(&deployment, &plan)?;
    }
    Ok(())
}

#[test]
fn resume_after_unlinks_does_not_require_intentionally_removed_root_witnesses() -> TestResult {
    for stage in [STAGE_DELETION_ROOT_RETRACTED, STAGE_DELETION_OBJECT_REMOVED] {
        let (dir, limits, input) = setup(stage, 40)?;
        let (mut deployment, _, plan) = prepare(&dir, limits, &input)?;
        let digest = plan.digest()?;
        let approval = plan.approval_digest(PRINCIPAL)?;
        let stop = cx("deletion-batches-unlink")?;
        stop.set_cancel_at_checkpoint_occurrence(stage, 2);
        assert!(matches!(commit_deletion(&mut deployment, digest, approval, PRINCIPAL, &stop), Err(DeletionError::Cancelled { .. })));
        drop(deployment);
        let mut deployment = open(&dir, limits)?;
        commit_deletion(&mut deployment, digest, approval, PRINCIPAL, &cx("deletion-batches-unlink-resume")?)?;
        assert_bounded_complete(&deployment, &plan)?;
    }
    Ok(())
}

#[test]
fn sensor_scope_uses_one_approval_and_preserves_a_shared_other_sensor_import() -> TestResult {
    let (dir, limits, input) = setup("scope", 40)?;
    let (mut deployment, first, _) = prepare(&dir, limits, &input)?;
    let context = cx("deletion-batches-scope")?;
    let mut second = input.clone();
    second.limits.max_batch_deltas = 7;
    let second = FileIngestAdapter::ingest(second, &context, &mut deployment)?;
    let mut outside = input.clone();
    outside.sensor_id = SensorId::parse("sensor:outside-deletion")?;
    let outside = FileIngestAdapter::ingest(outside, &context, &mut deployment)?;
    let plan = plan_scope_deletion(&deployment, &DeletionScope::Sensor(input.sensor_id.clone()), &context)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    assert_eq!(plan.imports.iter().copied().collect::<BTreeSet<_>>(), BTreeSet::from([first, second.import_identity]));
    commit_deletion(&mut deployment, plan.digest()?, plan.approval_digest(PRINCIPAL)?, PRINCIPAL, &context)?;
    assert_bounded_complete(&deployment, &plan)?;
    let retained = RetainedFileImport::open(&deployment, outside.import_identity, RetainedReadLimits::default(), &context)?;
    assert_eq!(retained.verify_source(&deployment, RetainedReadLimits::default(), &context)?, outside.input_sha256);
    Ok(())
}

#[test]
fn small_deletion_keeps_one_legacy_record_batch() -> TestResult {
    let (dir, _, input) = setup("legacy", 2)?;
    let limits = standard();
    let (mut deployment, _, plan) = prepare(&dir, limits, &input)?;
    let digest = plan.digest()?;
    let prefix = DeletionPlan::record_batch_id(digest);
    commit_deletion(&mut deployment, digest, plan.approval_digest(PRINCIPAL)?, PRINCIPAL, &cx("deletion-batches-legacy")?)?;
    let batches: Vec<_> = deployment.ledger().batches().iter()
        .filter(|batch| batch.batch_id.as_str().starts_with(&prefix)).collect();
    assert_eq!(batches.len(), 2);
    assert_eq!(batches[0].batch_id.as_str(), prefix);
    assert_eq!(batches[0].deltas.len(), 1 + plan.tombstones.len() + plan.retractions.len());
    assert_eq!(batches[1].batch_id.as_str(), DeletionPlan::completion_batch_id(digest));
    Ok(())
}

#[test]
fn journal_byte_limit_partitions_deletion_even_when_the_entry_count_fits() -> TestResult {
    let (probe_dir, mut limits, input) = setup("journal-probe", 64)?;
    limits.batch_entries_max = 16_384;
    let (probe, _, _) = prepare(&probe_dir, limits, &input)?;
    let import_max = probe.ledger().batches().iter()
        .map(|batch| fss_ledger::encode_batch(batch).map(|bytes| bytes.len()))
        .collect::<Result<Vec<_>, _>>()?.into_iter().max().ok_or("no import records")?;
    limits.journal_record_max_bytes = u32::try_from(import_max + 512)?;
    let dir = fresh_dir("deletion-batches-byte-bound")?.join("deployment");
    let (mut deployment, _, plan) = prepare(&dir, limits, &input)?;
    let digest = plan.digest()?;
    assert!(plan.tombstones.len() + plan.retractions.len() + 1 < limits.batch_entries_max);
    commit_deletion(&mut deployment, digest, plan.approval_digest(PRINCIPAL)?, PRINCIPAL, &cx("deletion-batches-byte-bound")?)?;
    let prefix = DeletionPlan::record_batch_id(digest);
    let records: Vec<_> = deployment.ledger().batches().iter()
        .filter(|batch| batch.batch_id.as_str().starts_with(&prefix)).collect();
    assert!(records.len() > 2, "the byte bound, not the count bound, must partition");
    for record in records {
        assert!(fss_ledger::encode_batch(record)?.len() <= limits.journal_record_max_bytes as usize);
    }
    Ok(())
}

#[test]
fn oversized_indivisible_plan_is_refused_before_any_deletion_object_is_staged() -> TestResult {
    let (dir, mut limits, input) = setup("plan-bound", 2)?;
    limits.batch_entries_max = 128;
    limits.spool_object_max_bytes = 4096;
    let context = cx("deletion-batches-plan-bound")?;
    let mut deployment = open(&dir, limits)?;
    for knob in 1..=4 {
        let mut request = input.clone();
        request.limits.max_batch_deltas = knob;
        FileIngestAdapter::ingest(request, &context, &mut deployment)?;
    }
    let plan = plan_scope_deletion(&deployment, &DeletionScope::Sensor(input.sensor_id.clone()), &context)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    assert!(plan.canonical_bytes()?.len() > limits.spool_object_max_bytes as usize);
    let count = deployment.publisher().spool().object_count();
    let occupied = deployment.publisher().spool().occupied_bytes()?;
    let anchor = deployment.current_anchor().clone();
    assert!(matches!(commit_deletion(&mut deployment, plan.digest()?, plan.approval_digest(PRINCIPAL)?, PRINCIPAL, &context), Err(DeletionError::Bound { limit: "spool_object_max_bytes" })));
    assert_eq!(deployment.publisher().spool().object_count(), count);
    assert_eq!(deployment.publisher().spool().occupied_bytes()?, occupied);
    assert_eq!(deployment.current_anchor(), &anchor);
    assert_no_unlinks(&deployment, &plan)?;
    Ok(())
}

#![forbid(unsafe_code)]
//! File-import part custody: real spool/root/ledger owners, not a mock publisher.
//! These are deterministic in-process fault tests, not power-loss qualification.

mod file_import_fault_support;

use std::cell::Cell;
use std::collections::BTreeSet;
use std::fs;

use file_import_fault_support::{TestResult, cx, fresh_dir, open, standard};
use fss_core::{CanonicalEncode, CaptureInterval, ContentDigest, TimestampNs};
use fss_object::ObjectManifest;
use fss_publication::{PublishCutPoint, RootLedgerOutcome};
use fss_reference::ingest::file_publication::{
    FilePublicationPlan, MAX_FILE_PUBLICATION_PARTS, MAX_FILE_PUBLICATION_PAYLOADS,
    STAGE_FILE_PART_PREFLIGHT, STAGE_FILE_PART_PUBLISH, STAGE_FILE_PART_ROOT,
};
use fss_reference::ingest::file_publication_recovery::{
    STAGE_FILE_PART_RECOVER, recover_file_publication,
};
use fss_reference::ingest::{FileImportManifest, RetainedReadLimits};
use fss_reference::{ADP_FILE_GENERATION, ADP_FILE_ROW_ID, FileIngestError, ReferenceDeployment};

fn payload(index: usize) -> Vec<u8> {
    (index as u64).to_be_bytes().to_vec()
}

fn digest(index: usize) -> ContentDigest {
    ContentDigest::sha256(&payload(index))
}

fn identity() -> ContentDigest {
    ContentDigest::sha256(b"file-part-contract")
}

fn validity() -> Result<CaptureInterval, fss_core::ContractError> {
    CaptureInterval::new(TimestampNs(0), TimestampNs(1_000_000_000))
}

fn metadata(plan: &FilePublicationPlan, count: usize) -> FileImportManifest {
    let source: Vec<_> = (0..count).flat_map(payload).collect();
    FileImportManifest {
        input_sha256: ContentDigest::sha256(&source),
        input_bytes: source.len() as u64,
        format: "mjpeg".to_owned(),
        detector_evidence: "synthetic-custody-only:no-media-claim".to_owned(),
        chunk_bytes: 8,
        ordered_chunks: (0..count).map(digest).collect(),
        segment_spans: Vec::new(),
        omission_spans: Vec::new(),
        capsule_ids: Vec::new(),
        limits_digest: ContentDigest::sha256(b"synthetic-limits"),
        adapter_id: ADP_FILE_ROW_ID.to_owned(),
        adapter_generation: ADP_FILE_GENERATION.to_owned(),
        part_roots: plan.part_roots(),
        capture_time_label: "unknown".to_owned(),
    }
}

fn stage(deployment: &mut ReferenceDeployment, count: usize) -> TestResult {
    for index in 0..count {
        assert_eq!(
            deployment.publisher_mut().stage_object(&payload(index))?,
            digest(index)
        );
    }
    Ok(())
}

#[test]
fn partition_boundaries_preserve_every_payload_exactly_once() -> TestResult {
    for limit in [1_usize, 2, 7, 64, 16_384] {
        for count in [0, limit.saturating_sub(1), limit, limit + 1, limit * 2 + 3] {
            let plan = FilePublicationPlan::new(identity(), (0..count).map(digest), limit)?;
            assert_eq!(plan.payloads().len(), count);
            assert_eq!(plan.parts().is_empty(), count < limit);
            let mut seen = BTreeSet::new();
            for (ordinal, part) in plan.parts().iter().enumerate() {
                assert!(part.slot().as_str().ends_with(&format!("-p{ordinal:06}")));
                assert!(part.manifest().children().len() <= limit);
                assert!(!part.manifest().children().is_empty());
                assert!(part.manifest().metadata_digest().is_none());
                for child in part.manifest().children() {
                    assert!(seen.insert(*child));
                }
            }
            if !plan.parts().is_empty() {
                assert_eq!(seen, plan.payloads().iter().copied().collect());
            }
        }
    }
    Ok(())
}

#[test]
fn plan_is_order_independent_and_deduplicates_references() -> TestResult {
    let first = FilePublicationPlan::new(identity(), (0..101).map(digest), 32)?;
    let second = FilePublicationPlan::new(
        identity(),
        (0..101).rev().flat_map(|n| [digest(n), digest(n)]),
        32,
    )?;
    assert_eq!(first, second);
    assert_ne!(
        first.part_roots(),
        FilePublicationPlan::new(digest(900), first.payloads().iter().copied(), 32)?.part_roots()
    );
    Ok(())
}

#[test]
fn infinite_input_and_excessive_part_count_are_bounded() -> TestResult {
    let polls = Cell::new(0_usize);
    let source = std::iter::repeat(digest(0)).inspect(|_| polls.set(polls.get() + 1));
    assert!(matches!(
        FilePublicationPlan::new(identity(), source, 32),
        Err(FileIngestError::SpoolCapacityExceeded {
            limit: "file_publication_payloads",
            ..
        })
    ));
    assert_eq!(polls.get(), MAX_FILE_PUBLICATION_PAYLOADS + 1);
    assert!(matches!(
        FilePublicationPlan::new(identity(), (0..=MAX_FILE_PUBLICATION_PARTS).map(digest), 1),
        Err(FileIngestError::SpoolCapacityExceeded {
            limit: "file_publication_parts",
            ..
        })
    ));
    assert!(FilePublicationPlan::new(identity(), [], 0).is_err());
    assert!(FilePublicationPlan::new(identity(), [], 16_385).is_err());
    Ok(())
}

#[test]
fn small_publications_keep_the_existing_root_bytes() -> TestResult {
    let plan = FilePublicationPlan::new(identity(), (0..3).map(digest), 32)?;
    let meta = metadata(&plan, 3);
    let expected = ObjectManifest::new(
        plan.slot().as_str(),
        (0..3).map(digest),
        Some(meta.canonical_digest()),
    )?;
    assert_eq!(plan.root_manifest(&meta)?, expected);
    assert_eq!(
        plan.root_manifest(&meta)?.canonical_bytes(),
        expected.canonical_bytes()
    );
    Ok(())
}

#[test]
fn mismatched_parts_and_unretained_source_chunks_are_refused() -> TestResult {
    let plan = FilePublicationPlan::new(identity(), (0..70).map(digest), 32)?;
    let mut meta = metadata(&plan, 70);
    let root = plan.root_manifest(&meta)?;
    assert_eq!(root.children(), &[meta.canonical_digest()]);
    meta.part_roots.reverse();
    assert!(plan.root_manifest(&meta).is_err());
    meta.part_roots = plan.part_roots();
    meta.ordered_chunks.push(digest(700));
    assert!(plan.root_manifest(&meta).is_err());
    Ok(())
}

#[test]
fn real_parts_survive_reopen_and_retry_without_new_ledger_batches() -> TestResult {
    let dir = fresh_dir("parts-reopen")?;
    let limits = standard();
    let plan = FilePublicationPlan::new(identity(), (0..70).map(digest), 32)?;
    let meta = metadata(&plan, 70);
    let mut dep = open(&dir, limits)?;
    stage(&mut dep, 70)?;
    let receipt = plan.publish(&mut dep, &meta, validity()?, &cx("parts-write")?)?;
    assert_eq!(receipt.parts.len(), 3);
    assert_eq!(dep.ledger().batches().len(), 4);
    assert!(
        dep.ledger()
            .batches()
            .iter()
            .all(|batch| batch.children.len() <= 32)
    );
    plan.verify(&dep, &meta, &cx("parts-verify")?)?;
    let anchor = dep.current_anchor().clone();
    drop(dep);
    let mut dep = open(&dir, limits)?;
    assert!(dep.publisher().recovery_report().is_clean());
    plan.verify(&dep, &meta, &cx("parts-cold-verify")?)?;
    let retry = plan.publish(&mut dep, &meta, validity()?, &cx("parts-retry")?)?;
    assert_eq!(retry.root.outcome, RootLedgerOutcome::AlreadyLedgered);
    assert!(
        retry
            .parts
            .iter()
            .all(|part| part.outcome == RootLedgerOutcome::AlreadyLedgered)
    );
    assert_eq!(dep.current_anchor(), &anchor);
    assert_eq!(dep.ledger().batches().len(), 4);
    // Publishing parts is not a final import batch and must not weaken the legacy reader gate.
    assert!(
        FileImportManifest::from_retained_bytes(
            &meta.canonical_bytes(),
            meta.canonical_digest(),
            RetainedReadLimits::default()
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn cancellation_keeps_a_part_prefix_incomplete_then_resumes_exactly() -> TestResult {
    for (label, checkpoint, occurrence, prefix) in [
        ("parts-pre", STAGE_FILE_PART_PREFLIGHT, 1, 0_usize),
        ("parts-first", STAGE_FILE_PART_PUBLISH, 1, 0),
        ("parts-second", STAGE_FILE_PART_PUBLISH, 2, 1),
        ("parts-third", STAGE_FILE_PART_PUBLISH, 3, 2),
        ("parts-root", STAGE_FILE_PART_ROOT, 1, 3),
    ] {
        let dir = fresh_dir(label)?;
        let limits = standard();
        let plan = FilePublicationPlan::new(identity(), (0..70).map(digest), 32)?;
        let meta = metadata(&plan, 70);
        let mut dep = open(&dir, limits)?;
        stage(&mut dep, 70)?;
        let cancelled = cx(label)?;
        cancelled.set_cancel_at_checkpoint_occurrence(checkpoint, occurrence);
        assert!(
            plan.publish(&mut dep, &meta, validity()?, &cancelled)
                .is_err()
        );
        assert_eq!(dep.publisher().visible_roots().count(), prefix);
        assert_eq!(dep.ledger().batches().len(), prefix);
        assert!(dep.publisher().root(plan.slot()).is_none());
        drop(dep);
        let mut dep = open(&dir, limits)?;
        plan.publish(&mut dep, &meta, validity()?, &cx("parts-resume")?)?;
        assert_eq!(dep.ledger().batches().len(), 4);
        plan.verify(&dep, &meta, &cx("parts-resumed-verify")?)?;
    }
    Ok(())
}

#[test]
fn every_root_crash_cut_recovers_without_duplicate_part_authority() -> TestResult {
    for (index, cut) in [
        PublishCutPoint::AfterChildrenVerified,
        PublishCutPoint::AfterManifestBody,
        PublishCutPoint::AfterRootTempWrite,
        PublishCutPoint::AfterRootRename,
    ]
    .into_iter()
    .enumerate()
    {
        let dir = fresh_dir(&format!("parts-crash-{index}"))?;
        let limits = standard();
        let plan = FilePublicationPlan::new(identity(), (0..70).map(digest), 32)?;
        let meta = metadata(&plan, 70);
        let mut dep = open(&dir, limits)?;
        stage(&mut dep, 70)?;
        dep.publisher_mut().inject_crash_at(cut);
        assert!(
            plan.publish(&mut dep, &meta, validity()?, &cx("parts-crash")?)
                .is_err()
        );
        assert!(dep.publisher().root(plan.slot()).is_none());
        drop(dep);
        let mut dep = open(&dir, limits)?;
        plan.publish(&mut dep, &meta, validity()?, &cx("parts-recover")?)?;
        assert_eq!(dep.ledger().batches().len(), 4);
        plan.verify(&dep, &meta, &cx("parts-recovered")?)?;
    }
    Ok(())
}

#[test]
fn missing_payload_or_conflicting_root_never_publishes_a_prefix() -> TestResult {
    let dir = fresh_dir("parts-missing")?;
    let plan = FilePublicationPlan::new(identity(), (0..70).map(digest), 32)?;
    let meta = metadata(&plan, 70);
    let mut dep = open(&dir, standard())?;
    stage(&mut dep, 69)?;
    let objects = dep.publisher().spool().object_count();
    assert!(
        plan.publish(&mut dep, &meta, validity()?, &cx("parts-missing")?)
            .is_err()
    );
    assert_eq!(dep.publisher().spool().object_count(), objects);
    assert_eq!(dep.publisher().visible_roots().count(), 0);
    assert!(dep.ledger().batches().is_empty());
    stage(&mut dep, 70)?;
    let last = plan.parts().last().ok_or("expected a part")?;
    dep.publisher_mut().verify_object(digest(0))?;
    let conflict = ObjectManifest::new(last.slot().as_str(), [digest(0)], None)?;
    dep.publisher_mut().stage_manifest(last.slot(), &conflict)?;
    dep.publish_and_commit(last.slot(), &conflict, validity()?, &cx("parts-conflict")?)?;
    let objects = dep.publisher().spool().object_count();
    assert!(
        plan.publish(&mut dep, &meta, validity()?, &cx("parts-conflict-retry")?)
            .is_err()
    );
    assert_eq!(dep.publisher().spool().object_count(), objects);
    assert_eq!(dep.publisher().visible_roots().count(), 1);
    assert_eq!(dep.ledger().batches().len(), 1);
    Ok(())
}

#[test]
fn missing_part_record_after_reopen_invalidates_the_aggregate() -> TestResult {
    let dir = fresh_dir("parts-lost-record")?;
    let limits = standard();
    let plan = FilePublicationPlan::new(identity(), (0..70).map(digest), 32)?;
    let meta = metadata(&plan, 70);
    let mut dep = open(&dir, limits)?;
    stage(&mut dep, 70)?;
    plan.publish(&mut dep, &meta, validity()?, &cx("parts-before-loss")?)?;
    let part = plan.parts().first().ok_or("expected a part")?;
    let record = dep
        .publisher()
        .root_dir()
        .join("roots")
        .join(format!("{}.root", part.slot()));
    drop(dep);
    fs::remove_file(record)?;
    let dep = open(&dir, limits)?;
    assert!(dep.publisher().root(plan.slot()).is_some());
    assert!(plan.verify(&dep, &meta, &cx("parts-after-loss")?).is_err());
    assert!(recover_file_publication(&dep, identity(), &meta, &cx("parts-recover-loss")?).is_err());
    Ok(())
}

#[test]
fn root_object_and_journal_capacity_are_checked_before_metadata_staging() -> TestResult {
    for case in 0..3 {
        let dir = fresh_dir(&format!("parts-capacity-{case}"))?;
        let mut limits = standard();
        match case {
            0 => limits.max_roots = 3,
            1 => limits.spool_object_max_bytes = 512,
            _ => limits.journal_record_max_bytes = 1024,
        }
        let plan = FilePublicationPlan::new(identity(), (0..70).map(digest), 32)?;
        let meta = metadata(&plan, 70);
        let mut dep = open(&dir, limits)?;
        stage(&mut dep, 70)?;
        let objects = dep.publisher().spool().object_count();
        let occupied = dep.publisher().spool().occupied_bytes()?;
        assert!(matches!(
            plan.publish(&mut dep, &meta, validity()?, &cx("parts-capacity")?),
            Err(FileIngestError::SpoolCapacityExceeded { .. })
        ));
        assert_eq!(dep.publisher().spool().object_count(), objects);
        assert_eq!(dep.publisher().spool().occupied_bytes()?, occupied);
        assert_eq!(dep.publisher().visible_roots().count(), 0);
        assert!(dep.ledger().batches().is_empty());
    }
    Ok(())
}

#[test]
fn a_retry_cannot_relabel_the_existing_publication_validity() -> TestResult {
    let dir = fresh_dir("parts-validity")?;
    let plan = FilePublicationPlan::new(identity(), (0..70).map(digest), 32)?;
    let meta = metadata(&plan, 70);
    let mut dep = open(&dir, standard())?;
    stage(&mut dep, 70)?;
    plan.publish(&mut dep, &meta, validity()?, &cx("parts-validity-first")?)?;
    let anchor = dep.current_anchor().clone();
    let changed = CaptureInterval::new(TimestampNs(1), TimestampNs(2))?;
    assert!(
        plan.publish(&mut dep, &meta, changed, &cx("parts-validity-retry")?)
            .is_err()
    );
    assert_eq!(dep.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn reconstructs_flat_and_partitioned_plans_without_the_original_payload_list() -> TestResult {
    for count in [3, 70] {
        let dir = fresh_dir(&format!("parts-reconstruct-{count}"))?;
        let limits = standard();
        let plan = FilePublicationPlan::new(identity(), (0..count).map(digest), 32)?;
        let meta = metadata(&plan, count);
        let mut dep = open(&dir, limits)?;
        stage(&mut dep, count)?;
        let receipt = plan.publish(&mut dep, &meta, validity()?, &cx("parts-original")?)?;
        let root = receipt.root.root;
        let anchor = dep.current_anchor().clone();
        drop(plan);
        drop(dep);
        let mut dep = open(&dir, limits)?;
        let recovered = recover_file_publication(&dep, identity(), &meta, &cx("parts-rebuild")?)?;
        assert_eq!(recovered.payloads().len(), count);
        assert_eq!(recovered.root_manifest(&meta)?.root(), root);
        assert_eq!(dep.current_anchor(), &anchor);
        let retry = recovered.publish(&mut dep, &meta, validity()?, &cx("parts-rebuild-retry")?)?;
        assert_eq!(retry.root.outcome, RootLedgerOutcome::AlreadyLedgered);
        assert_eq!(dep.current_anchor(), &anchor);
    }
    Ok(())
}

#[test]
fn reconstruction_rejects_omitted_reordered_foreign_and_unbound_metadata() -> TestResult {
    let dir = fresh_dir("parts-reconstruct-refusals")?;
    let plan = FilePublicationPlan::new(identity(), (0..70).map(digest), 32)?;
    let meta = metadata(&plan, 70);
    let mut dep = open(&dir, standard())?;
    stage(&mut dep, 70)?;
    plan.publish(&mut dep, &meta, validity()?, &cx("parts-reconstruct-base")?)?;
    let anchor = dep.current_anchor().clone();
    for case in 0..4 {
        let mut changed = meta.clone();
        match case {
            0 => {
                let _ = changed.part_roots.pop();
            }
            1 => changed.part_roots.reverse(),
            2 => changed.part_roots[0] = digest(900),
            _ => changed.detector_evidence = "unretained replacement".to_owned(),
        }
        assert!(
            recover_file_publication(&dep, identity(), &changed, &cx("parts-reconstruct-bad")?)
                .is_err()
        );
    }
    assert_eq!(dep.current_anchor(), &anchor);
    Ok(())
}

#[test]
fn reconstruction_cancellation_is_read_only() -> TestResult {
    let dir = fresh_dir("parts-reconstruct-cancel")?;
    let plan = FilePublicationPlan::new(identity(), (0..70).map(digest), 32)?;
    let meta = metadata(&plan, 70);
    let mut dep = open(&dir, standard())?;
    stage(&mut dep, 70)?;
    plan.publish(
        &mut dep,
        &meta,
        validity()?,
        &cx("parts-reconstruct-ready")?,
    )?;
    let anchor = dep.current_anchor().clone();
    let objects = dep.publisher().spool().object_count();
    for occurrence in [1, 3, 5] {
        let cancelled = cx("parts-reconstruct-cancel")?;
        cancelled.set_cancel_at_checkpoint_occurrence(STAGE_FILE_PART_RECOVER, occurrence);
        assert!(matches!(
            recover_file_publication(&dep, identity(), &meta, &cancelled),
            Err(FileIngestError::CancellationRequested {
                stage: STAGE_FILE_PART_RECOVER
            })
        ));
        assert_eq!(dep.current_anchor(), &anchor);
        assert_eq!(dep.publisher().spool().object_count(), objects);
    }
    Ok(())
}

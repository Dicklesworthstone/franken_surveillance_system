#![forbid(unsafe_code)]
// `DeletionIndex::from_batches` readers must return the library API error type.
#![allow(clippy::result_large_err)]
//! Metadata-only recovery refuses false completion and accepts every genuine partial prefix.
//! Mutations operate on copied transcripts, never rewrite the real authority journal.

mod file_import_fault_support;

use std::collections::BTreeSet;
use std::fs;

use file_import_fault_support::{TestResult, cx, fixture, fresh_dir, open, request, standard};
use fss_core::{BatchId, ContentDigest, EvidenceDeltaBatch, ObjectId, OperationId, Plane};
use fss_reference::deletion::{
    CommitReceipt, DeletionCompletion, DeletionError, DeletionIndex, DeletionPlan, commit_deletion,
    has_records, plan_deletion,
};
use fss_reference::{DeploymentLimits, FileIngestAdapter, ReferenceDeployment};

type TestValue<T> = Result<T, Box<dyn std::error::Error>>;
const PRINCIPAL: &str = "operator:deletion-proof";

fn completed(label: &str, multipart: bool) -> TestValue<(ReferenceDeployment, CommitReceipt)> {
    let dir = fresh_dir(&format!("deletion-proof-{label}"))?;
    let frame = fs::read(fixture("jpeg/gray_16x16_flat.jpg")?)?;
    let source = dir.join("source.mjpeg");
    fs::write(&source, frame.repeat(if multipart { 40 } else { 2 }))?;
    let limits = if multipart {
        DeploymentLimits {
            batch_entries_max: 16,
            manifest_children_max: 8,
            ..standard()
        }
    } else {
        standard()
    };
    let context = cx("deletion-proof")?;
    let mut deployment = open(&dir.join("deployment"), limits)?;
    let imported = FileIngestAdapter::ingest(
        request(&source, frame.len() as u64, 8)?,
        &context,
        &mut deployment,
    )?;
    let plan = plan_deletion(&deployment, imported.import_identity, &context)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    let receipt = commit_deletion(
        &mut deployment,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &context,
    )?;
    Ok((deployment, receipt))
}

fn index(
    deployment: &ReferenceDeployment,
    batches: &[EvidenceDeltaBatch],
) -> Result<DeletionIndex, DeletionError> {
    DeletionIndex::from_batches(batches, |digest| {
        deployment
            .publisher()
            .spool()
            .read(digest)
            .map_err(DeletionError::from)
    })
}

fn first(batches: &[EvidenceDeltaBatch], digest: ContentDigest) -> TestValue<usize> {
    batches
        .iter()
        .position(|batch| batch.batch_id.as_str() == DeletionPlan::record_batch_id(digest))
        .ok_or_else(|| "missing initial deletion batch".into())
}

fn part_positions(batches: &[EvidenceDeltaBatch], digest: ContentDigest) -> Vec<usize> {
    let prefix = format!("{}:part:", DeletionPlan::record_batch_id(digest));
    batches
        .iter()
        .enumerate()
        .filter(|(_, batch)| batch.batch_id.as_str().starts_with(&prefix))
        .map(|(position, _)| position)
        .collect()
}

fn refresh(batch: &mut EvidenceDeltaBatch) {
    batch.batch_digest = batch.computed_digest();
}

#[test]
fn all_valid_prefixes_deny_the_full_closure_and_only_the_last_is_complete() -> TestResult {
    for multipart in [false, true] {
        let (deployment, receipt) = completed(&format!("prefix-{multipart}"), multipart)?;
        let batches = deployment.ledger().batches();
        let first = first(batches, receipt.plan_digest)?;
        assert!(index(&deployment, &batches[..first])?.is_empty());
        let allowed = BTreeSet::from([receipt.plan_digest, receipt.completion_digest]);
        for end in first + 1..=batches.len() {
            let recovered: DeletionIndex =
                DeletionIndex::from_batches(&batches[..end], |digest| {
                    assert!(
                        allowed.contains(&digest),
                        "index must never read deleted source bytes"
                    );
                    deployment
                        .publisher()
                        .spool()
                        .read(digest)
                        .map_err(DeletionError::from)
                })?;
            let entry = recovered.plan(receipt.plan_digest).ok_or("missing plan")?;
            assert_eq!(entry.is_complete(), end == batches.len());
            assert_eq!(recovered.deleted_objects(), receipt.plan.deleted_set());
            for import in &receipt.plan.imports {
                assert_eq!(
                    recovered.import(*import).map(|entry| entry.plan_digest),
                    Some(receipt.plan_digest)
                );
            }
        }
    }
    Ok(())
}

#[test]
fn deleting_any_transition_part_cannot_leave_a_complete_index() -> TestResult {
    let (deployment, receipt) = completed("missing-part", true)?;
    let batches = deployment.ledger().batches();
    let positions = part_positions(batches, receipt.plan_digest);
    assert!(positions.len() > 1);
    for at in positions {
        let mut damaged = batches.to_vec();
        damaged.remove(at);
        assert!(matches!(
            index(&deployment, &damaged),
            Err(DeletionError::RecordMismatch)
        ));
    }
    Ok(())
}

#[test]
fn deleting_or_rebinding_one_transition_is_not_hidden_by_valid_completion_bytes() -> TestResult {
    let (deployment, receipt) = completed("transition", true)?;
    let batches = deployment.ledger().batches();
    for at in part_positions(batches, receipt.plan_digest) {
        for case in 0..4 {
            let mut damaged = batches.to_vec();
            match case {
                0 => {
                    damaged[at].deltas.remove(0);
                }
                1 => damaged[at].deltas[0].payload_digest = ContentDigest::sha256(b"wrong plan"),
                2 => damaged[at].deltas[0].new_generation += 1,
                _ => damaged[at].deltas[0].object_id = ObjectId::parse("object:foreign")?,
            }
            refresh(&mut damaged[at]);
            assert!(matches!(
                index(&deployment, &damaged),
                Err(DeletionError::RecordMismatch)
            ));
        }
    }
    Ok(())
}

#[test]
fn exact_plan_digest_does_not_authorize_changed_completion_counts_or_omissions() -> TestResult {
    let (deployment, receipt) = completed("completion-payload", true)?;
    assert!(!receipt.completion.not_proven.is_empty());
    for case in 0..4 {
        let mut completion = receipt.completion.clone();
        match case {
            0 => completion.objects_unlinked += 1,
            1 => completion.bytes_unlinked += 1,
            2 => completion.roots_retracted += 1,
            _ => completion.not_proven.clear(),
        }
        let bytes = completion.canonical_bytes()?;
        let digest = ContentDigest::sha256(&bytes);
        assert_eq!(
            DeletionCompletion::decode(&bytes, digest)?.plan_digest,
            receipt.plan_digest
        );
        let mut batches = deployment.ledger().batches().to_vec();
        let last = batches.last_mut().ok_or("missing completion")?;
        last.deltas[0].payload_digest = digest;
        last.children = vec![receipt.plan_digest, digest];
        last.children.sort_unstable();
        refresh(last);
        let recovered: Result<DeletionIndex, DeletionError> =
            DeletionIndex::from_batches(&batches, |requested| {
                if requested == digest {
                    Ok(bytes.clone())
                } else {
                    deployment
                        .publisher()
                        .spool()
                        .read(requested)
                        .map_err(DeletionError::from)
                }
            });
        assert!(matches!(recovered, Err(DeletionError::RecordMismatch)));
    }
    Ok(())
}

#[test]
fn completion_authority_fields_and_children_are_exact() -> TestResult {
    let (deployment, _) = completed("completion-authority", true)?;
    for case in 0..8 {
        let mut batches = deployment.ledger().batches().to_vec();
        let last = batches.last_mut().ok_or("missing completion")?;
        match case {
            0 => last.deltas[0].witness_digest = None,
            1 => last.deltas[0].prior_generation = None,
            2 => last.deltas[0].new_generation = 3,
            3 => last.deltas[0].plane = Plane::Cognition,
            4 => last.deltas[0].delta_id = "delta:unrelated".to_owned(),
            5 => last.deltas[0].object_id = ObjectId::parse("object:unrelated")?,
            6 => last.children.clear(),
            _ => last.deltas[0].operation_id = Some(OperationId::parse("operation:unrelated")?),
        }
        refresh(last);
        assert!(matches!(
            index(&deployment, &batches),
            Err(DeletionError::RecordMismatch)
        ));
    }
    Ok(())
}

#[test]
fn duplicate_reordered_and_wrong_ordinal_batches_are_refused() -> TestResult {
    let (deployment, receipt) = completed("order", true)?;
    let batches = deployment.ledger().batches();
    let header = first(batches, receipt.plan_digest)?;
    let parts = part_positions(batches, receipt.plan_digest);
    assert!(parts.len() > 1);
    for case in 0..5 {
        let mut damaged = batches.to_vec();
        match case {
            0 => damaged.insert(header + 1, damaged[header].clone()),
            1 => damaged.push(damaged.last().ok_or("completion")?.clone()),
            2 => damaged.swap(parts[0], parts[1]),
            3 => {
                damaged[parts[0]].batch_id = BatchId::parse(format!(
                    "{}:part:0000000009",
                    DeletionPlan::record_batch_id(receipt.plan_digest)
                ))?;
                refresh(&mut damaged[parts[0]]);
            }
            _ => {
                let completion = damaged.pop().ok_or("completion")?;
                damaged.insert(header + 1, completion);
            }
        }
        assert!(matches!(
            index(&deployment, &damaged),
            Err(DeletionError::RecordMismatch)
        ));
    }
    Ok(())
}

#[test]
fn orphan_authority_and_relabelled_header_never_bypass_the_deletion_scan() -> TestResult {
    let (deployment, receipt) = completed("orphan", true)?;
    let batches = deployment.ledger().batches();
    let header = first(batches, receipt.plan_digest)?;
    let part = part_positions(batches, receipt.plan_digest)[0];
    for batch in [&batches[part], batches.last().ok_or("completion")?] {
        assert!(has_records(std::slice::from_ref(batch)));
        assert!(matches!(
            index(&deployment, std::slice::from_ref(batch)),
            Err(DeletionError::RecordMismatch)
        ));
    }
    let mut renamed = batches[header].clone();
    renamed.deltas[0].family = "not_a_deletion".to_owned();
    refresh(&mut renamed);
    assert!(has_records(std::slice::from_ref(&renamed)));
    assert!(matches!(
        index(&deployment, &[renamed]),
        Err(DeletionError::RecordMismatch)
    ));
    Ok(())
}

#[test]
fn header_shape_basis_and_digest_must_match_the_sealed_plan() -> TestResult {
    let (deployment, receipt) = completed("header", true)?;
    let batches = deployment.ledger().batches();
    let header = first(batches, receipt.plan_digest)?;
    for case in 0..5 {
        let mut damaged = batches[..=header].to_vec();
        let last = damaged.last_mut().ok_or("header")?;
        match case {
            0 => last.deltas[0].plane = Plane::Cognition,
            1 => last.deltas[0].witness_digest = Some(receipt.plan_digest),
            2 => last.children.clear(),
            3 => last.basis_anchor.state_root = ContentDigest::sha256(b"another basis"),
            _ => last.batch_digest = ContentDigest::sha256(b"invalid batch digest"),
        }
        if case != 4 {
            refresh(last);
        }
        assert!(matches!(
            index(&deployment, &damaged),
            Err(DeletionError::RecordMismatch)
        ));
    }
    Ok(())
}

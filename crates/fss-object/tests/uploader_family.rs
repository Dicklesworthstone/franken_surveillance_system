#![forbid(unsafe_code)]
//! Owned-upload regressions: runtime authority, cancellation, budgets and uncertain I/O.

mod multipart_support;

use std::collections::BTreeSet;

use fss_core::{
    BudgetVector, ContentDigest, DigestAlgorithm, ObligationState, OperationId, RegionState,
    RuntimeGrant, TaskId, TaskOutcome, TimestampNs,
};
use fss_object::multipart::{MultipartError, MultipartPhase, TransportOperation};
use fss_object::planner::{ChunkPolicy, MIN_PART_SIZE};
use fss_object::uploader::{StagedUpload, UploaderError, minimum_upload_budget};
use multipart_support::{MemoryTransport, RESOURCE, Test, budget, property, spec};

fn policy() -> ChunkPolicy {
    ChunkPolicy {
        part_size: MIN_PART_SIZE,
    }
}
fn root() -> ContentDigest {
    ContentDigest::sha256(b"upload-root")
}
fn stage<'a>(
    parent: &'a mut fss_runtime::authority::AuthorityCx,
    tree: &mut fss_core::RegionTree,
    transport: &'a mut MemoryTransport,
) -> Result<StagedUpload<'a, MemoryTransport>, Box<dyn std::error::Error>> {
    Ok(StagedUpload::stage(
        parent,
        tree,
        transport,
        OperationId::parse("operation:upload")?,
        3,
        policy(),
        root(),
        spec("operation:upload", budget())?,
        RESOURCE,
        TimestampNs(1),
    )?)
}
fn emit(property: &str, cases: usize) {
    println!(
        "{{\"family\":\"FSS-063\",\"property\":\"{property}\",\"cases\":{cases},\"verdict\":\"pass\"}}"
    );
}

#[test]
fn happy_path_child_owns_obligation_io_and_quiescence_with_refund() -> Test {
    let (root_owner, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let before = parent.budget().remaining();
    let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
    let region = upload.region().clone();
    let obligation = upload.obligation().clone();
    assert_eq!(
        tree.get(&region)?.obligations[&obligation].state,
        ObligationState::Pending
    );
    assert!(
        tree.get(&fss_core::RegionId::new("region:property")?)?
            .obligations
            .is_empty()
    );
    assert!(store.borrow().calls.is_empty());
    upload.upload_chunks(&tree, || TimestampNs(2), |_| b"abc".to_vec())?;
    upload.upload_chunks(
        &tree,
        || TimestampNs(2),
        |_| panic!("confirmed payload must not be reread"),
    )?;
    assert_eq!(upload.confirmed_parts(), 1);
    assert_eq!(upload.budget().consumed().bytes, 3);
    assert_eq!(upload.budget().consumed().network_bytes, 3);
    let receipt = upload.finish(&mut tree, TimestampNs(3))?;
    assert_eq!(upload.finish(&mut tree, TimestampNs(4))?, receipt);
    let node = tree.get(&region)?;
    assert_eq!(node.state, RegionState::Closed);
    assert_eq!(
        node.obligations[&obligation].proof_digest,
        Some(receipt.digest())
    );
    assert!(node.quiescence_proof.is_some());
    assert!(
        store
            .borrow()
            .regions
            .iter()
            .all(|actual| *actual == region)
    );
    drop(upload);
    assert_eq!(before.bytes - parent.budget().remaining().bytes, 3);
    assert_eq!(
        before.storage_operations - parent.budget().remaining().storage_operations,
        3
    );
    root_owner.request_cancellation(&mut tree, TimestampNs(5))?;
    parent.begin_drain(&mut tree, TimestampNs(5))?;
    parent.finalize(&mut tree, TimestampNs(5))?;
    emit("child-owned-terminal-refund", 10);
    Ok(())
}

#[test]
fn cancellation_is_pending_until_explicit_abort_and_child_closure() -> Test {
    let (root_owner, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
    upload.start(&tree, TimestampNs(2))?;
    let region = upload.region().clone();
    let obligation = upload.obligation().clone();
    root_owner.request_cancellation(&mut tree, TimestampNs(3))?;
    assert!(matches!(
        upload.upload_chunks(
            &tree,
            || TimestampNs(3),
            |_| panic!("cancelled source access")
        ),
        Err(UploaderError::CancellationRequested { confirmed_parts: 0 })
    ));
    assert_eq!(upload.phase(), MultipartPhase::Uploading);
    assert_eq!(
        tree.get(&region)?.obligations[&obligation].state,
        ObligationState::Pending
    );
    assert!(upload.finish(&mut tree, TimestampNs(3)).is_err());
    let abort = upload.cancel(&mut tree, TimestampNs(4))?;
    assert_eq!(abort.confirmed_parts, 0);
    assert_eq!(
        tree.get(&region)?.obligations[&obligation].state,
        ObligationState::Cancelled
    );
    assert_eq!(tree.get(&region)?.state, RegionState::Closed);
    assert_eq!(
        store.borrow().calls,
        vec![TransportOperation::Initiate, TransportOperation::Abort]
    );
    emit("cancellation-requires-explicit-drain", 6);
    Ok(())
}

#[test]
fn dropped_owner_leaves_child_pending_and_parent_cannot_finalize() -> Test {
    let (root_owner, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport::default();
    let before = parent.budget().remaining();
    let upload = stage(&mut parent, &mut tree, &mut transport)?;
    let region = upload.region().clone();
    let obligation = upload.obligation().clone();
    drop(upload);
    let report = fss_runtime::obligation::tree_report(&tree);
    assert!(report.iter().any(|row| row.region == region.as_str()
        && row.leaked.iter().any(|leak| leak.id == obligation.as_str())));
    assert_eq!(
        parent.budget().remaining().bytes,
        before.bytes - budget().bytes
    );
    root_owner.request_cancellation(&mut tree, TimestampNs(3))?;
    parent.begin_drain(&mut tree, TimestampNs(3))?;
    assert!(parent.finalize(&mut tree, TimestampNs(3)).is_err());
    emit("unfinished-child-leak-visible", 3);
    Ok(())
}

#[test]
fn inadequate_grants_scopes_and_allowance_refuse_without_region_or_io() -> Test {
    for kind in 0..4 {
        let (_root_owner, mut parent, mut tree) = property()?;
        let mut transport = MemoryTransport::default();
        let before = parent.budget().remaining();
        let count = tree.iter().count();
        let mut child = spec("operation:upload", budget())?;
        match kind {
            0 => child.capabilities.clear(),
            1 => child.budgets = BudgetVector::ZERO,
            2 => child.deadline = Some(TimestampNs(1)),
            _ => {
                let restricted = parent.grants().clone().with_scope(
                    RuntimeGrant::AdapterNet,
                    BTreeSet::from(["archive:other".into()]),
                );
                parent.narrow_grants(restricted)?;
            }
        }
        assert!(
            StagedUpload::stage(
                &mut parent,
                &mut tree,
                &mut transport,
                OperationId::parse("operation:upload")?,
                3,
                policy(),
                root(),
                child,
                RESOURCE,
                TimestampNs(1)
            )
            .is_err()
        );
        assert_eq!(tree.iter().count(), count);
        assert_eq!(parent.budget().remaining(), before);
        assert!(transport.store.borrow().calls.is_empty());
    }
    emit("preparation-refusal-is-effect-free", 4);
    Ok(())
}

#[test]
fn lost_completion_or_abort_ack_remains_pending_then_reconciles_terminal() -> Test {
    for fault in [TransportOperation::Complete, TransportOperation::Abort] {
        let (root_owner, mut parent, mut tree) = property()?;
        let mut transport = MemoryTransport::default();
        let store = transport.store.clone();
        let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
        upload.upload_chunks(&tree, || TimestampNs(2), |_| b"abc".to_vec())?;
        let region = upload.region().clone();
        let obligation = upload.obligation().clone();
        store.borrow_mut().fault_once = Some(fault);
        if fault == TransportOperation::Complete {
            assert!(upload.finish(&mut tree, TimestampNs(3)).is_err());
        } else {
            assert!(upload.cancel(&mut tree, TimestampNs(3)).is_err());
        }
        assert_eq!(
            tree.get(&region)?.obligations[&obligation].state,
            ObligationState::Pending
        );
        assert_eq!(upload.phase(), MultipartPhase::Uncertain(fault));
        root_owner.request_cancellation(&mut tree, TimestampNs(4))?;
        store.borrow_mut().unknown = true;
        assert_eq!(
            upload.reconcile(&mut tree, TimestampNs(4))?,
            MultipartPhase::Uncertain(fault)
        );
        assert_eq!(
            tree.get(&region)?.obligations[&obligation].state,
            ObligationState::Pending
        );
        store.borrow_mut().unknown = false;
        let terminal = upload.reconcile(&mut tree, TimestampNs(5))?;
        assert_eq!(
            terminal,
            if fault == TransportOperation::Complete {
                MultipartPhase::Completed
            } else {
                MultipartPhase::Aborted
            }
        );
        assert_eq!(tree.get(&region)?.state, RegionState::Closed);
        assert_eq!(
            store
                .borrow()
                .calls
                .iter()
                .filter(|op| **op == fault)
                .count(),
            1
        );
    }
    emit("lost-terminal-ack-owned-reconciliation", 2);
    Ok(())
}

#[test]
fn scoped_publication_revocation_blocks_finish_but_allows_owned_cleanup() -> Test {
    let (_root_owner, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
    upload.upload_chunks(&tree, || TimestampNs(2), |_| b"abc".to_vec())?;
    let restricted = upload.grants().clone().with_scope(
        RuntimeGrant::ObjectPublish,
        BTreeSet::from(["archive:other".into()]),
    );
    upload.narrow_grants(restricted)?;
    assert!(matches!(
        upload.finish(&mut tree, TimestampNs(3)),
        Err(UploaderError::Protocol(MultipartError::Authority(_)))
    ));
    assert!(!store.borrow().calls.contains(&TransportOperation::Complete));
    upload.cancel(&mut tree, TimestampNs(4))?;
    emit("actual-child-grant-revalidation", 2);
    Ok(())
}

#[test]
fn deadline_after_source_callback_blocks_part_dispatch_and_keeps_abort_capacity() -> Test {
    let (_root_owner, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let mut child = spec("operation:upload", minimum_upload_budget(3, policy())?)?;
    child.deadline = Some(TimestampNs(5));
    let mut upload = StagedUpload::stage(
        &mut parent,
        &mut tree,
        &mut transport,
        OperationId::parse("operation:upload")?,
        3,
        policy(),
        root(),
        child,
        RESOURCE,
        TimestampNs(1),
    )?;
    let mut times = [TimestampNs(2), TimestampNs(3), TimestampNs(5)].into_iter();
    assert!(matches!(
        upload.upload_chunks(
            &tree,
            || times.next().unwrap_or(TimestampNs(5)),
            |_| b"abc".to_vec()
        ),
        Err(UploaderError::Protocol(MultipartError::Deadline))
    ));
    assert_eq!(store.borrow().calls, vec![TransportOperation::Initiate]);
    assert_eq!(upload.budget().consumed().bytes, 0);
    upload.cancel(&mut tree, TimestampNs(6))?;
    emit("deadline-rechecked-after-source-read", 3);
    Ok(())
}

#[test]
fn failed_parts_are_charged_and_retry_cannot_spend_cleanup_reserve() -> Test {
    let (_root_owner, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let mut allowance = minimum_upload_budget(3, policy())?;
    allowance.bytes = 6;
    allowance.network_bytes = 6;
    let mut upload = StagedUpload::stage(
        &mut parent,
        &mut tree,
        &mut transport,
        OperationId::parse("operation:upload")?,
        3,
        policy(),
        root(),
        spec("operation:upload", allowance)?,
        RESOURCE,
        TimestampNs(1),
    )?;
    upload.start(&tree, TimestampNs(2))?;
    store.borrow_mut().fault_once = Some(TransportOperation::UploadPart);
    store.borrow_mut().fail_before_effect = true;
    assert!(
        upload
            .upload_part(&tree, TimestampNs(3), 0, b"abc")
            .is_err()
    );
    assert_eq!(upload.budget().consumed().bytes, 3);
    store.borrow_mut().unknown = true;
    upload.reconcile(&mut tree, TimestampNs(4))?;
    store.borrow_mut().unknown = false;
    upload.reconcile(&mut tree, TimestampNs(4))?;
    upload.upload_part(&tree, TimestampNs(5), 0, b"abc")?;
    assert_eq!(upload.budget().consumed().bytes, 6);
    assert_eq!(upload.confirmed_parts(), 1);
    assert_eq!(upload.budget().remaining().storage_operations, 1);
    assert!(matches!(
        upload.finish(&mut tree, TimestampNs(6)),
        Err(UploaderError::Protocol(MultipartError::CleanupReserve))
    ));
    upload.cancel(&mut tree, TimestampNs(6))?;
    emit("charged-retry-preserves-cleanup", 4);
    Ok(())
}

#[test]
fn foreign_tree_cannot_trigger_upload_or_clear_owning_obligation() -> Test {
    let (_root_owner, mut parent, mut tree) = property()?;
    let (_other_root, _other_parent, mut wrong_tree) = property()?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
    let region = upload.region().clone();
    let obligation = upload.obligation().clone();
    assert!(upload.start(&wrong_tree, TimestampNs(2)).is_err());
    assert!(upload.cancel(&mut wrong_tree, TimestampNs(2)).is_err());
    assert!(store.borrow().calls.is_empty());
    assert_eq!(
        tree.get(&region)?.obligations[&obligation].state,
        ObligationState::Pending
    );
    let abort = upload.cancel(&mut tree, TimestampNs(2))?;
    assert!(abort.upload.is_none());
    assert!(store.borrow().calls.is_empty());
    emit("foreign-tree-refuses-before-io", 3);
    Ok(())
}

#[test]
fn minimal_allowance_can_reconcile_lost_abort_ack_with_its_final_operation() -> Test {
    let (_root_owner, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let child = spec("operation:upload", minimum_upload_budget(3, policy())?)?;
    let mut upload = StagedUpload::stage(
        &mut parent,
        &mut tree,
        &mut transport,
        OperationId::parse("operation:upload")?,
        3,
        policy(),
        root(),
        child,
        RESOURCE,
        TimestampNs(1),
    )?;
    upload.upload_chunks(&tree, || TimestampNs(2), |_| b"abc".to_vec())?;
    store.borrow_mut().fault_once = Some(TransportOperation::Complete);
    store.borrow_mut().fail_before_effect = true;
    assert!(upload.finish(&mut tree, TimestampNs(3)).is_err());
    assert_eq!(
        upload.reconcile(&mut tree, TimestampNs(4))?,
        MultipartPhase::Uploading
    );
    store.borrow_mut().fault_once = Some(TransportOperation::Abort);
    store.borrow_mut().fail_before_effect = false;
    assert!(upload.cancel(&mut tree, TimestampNs(5)).is_err());
    assert_eq!(upload.budget().remaining().storage_operations, 1);
    assert_eq!(
        upload.reconcile(&mut tree, TimestampNs(6))?,
        MultipartPhase::Aborted
    );
    assert_eq!(upload.budget().remaining().storage_operations, 0);
    assert_eq!(tree.get(upload.region())?.state, RegionState::Closed);
    emit("final-operation-reconciles-abort", 4);
    Ok(())
}

#[test]
fn transport_framing_is_metered_by_the_same_child_and_refunded_exactly() -> Test {
    let (_root_owner, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport::default();
    transport.store.borrow_mut().envelope_bytes = 4;
    let before = parent.budget().remaining();
    let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
    upload.upload_chunks(&tree, || TimestampNs(2), |_| b"abc".to_vec())?;
    upload.finish(&mut tree, TimestampNs(3))?;
    assert_eq!(upload.budget().consumed().bytes, 15);
    assert_eq!(upload.budget().consumed().network_bytes, 15);
    drop(upload);
    assert_eq!(before.bytes - parent.budget().remaining().bytes, 15);
    assert_eq!(
        before.network_bytes - parent.budget().remaining().network_bytes,
        15
    );
    emit("transport-envelope-accounted", 4);
    Ok(())
}

#[test]
fn duplicate_preparation_cannot_charge_again_or_replace_the_pending_child() -> Test {
    let (_root_owner, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport::default();
    let first = stage(&mut parent, &mut tree, &mut transport)?;
    let region = first.region().clone();
    let obligation = first.obligation().clone();
    drop(first);
    let remaining = parent.budget().remaining();
    let count = tree.iter().count();
    assert!(stage(&mut parent, &mut tree, &mut transport).is_err());
    assert_eq!(parent.budget().remaining(), remaining);
    assert_eq!(tree.iter().count(), count);
    assert_eq!(
        tree.get(&region)?.obligations[&obligation].state,
        ObligationState::Pending
    );
    assert!(transport.store.borrow().calls.is_empty());
    emit("duplicate-owner-preparation-refused", 4);
    Ok(())
}

#[test]
fn changed_obligation_blocks_every_provider_and_source_boundary() -> Test {
    for boundary in 0..6 {
        let (_root_owner, mut parent, mut tree) = property()?;
        let mut transport = MemoryTransport::default();
        let store = transport.store.clone();
        let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
        if boundary != 0 {
            upload.start(&tree, TimestampNs(2))?;
        }
        if boundary == 3 {
            upload.upload_part(&tree, TimestampNs(3), 0, b"abc")?;
        } else if boundary == 5 {
            store.borrow_mut().fault_once = Some(TransportOperation::UploadPart);
            assert!(
                upload
                    .upload_part(&tree, TimestampNs(3), 0, b"abc")
                    .is_err()
            );
        }
        let region = upload.region().clone();
        let obligation = upload.obligation().clone();
        let unrelated_proof = ContentDigest::sha256(b"different owner's outcome");
        tree.resolve_obligation(
            &region,
            &obligation,
            ObligationState::Verified,
            Some(unrelated_proof),
            None,
        )?;
        let phase = upload.phase();
        let consumed = *upload.budget().consumed();
        let calls = store.borrow().calls.clone();
        let result = match boundary {
            0 => upload.start(&tree, TimestampNs(4)),
            1 => upload
                .upload_part(&tree, TimestampNs(4), 0, b"abc")
                .map(|_| ()),
            2 => upload.upload_chunks(
                &tree,
                || TimestampNs(4),
                |_| panic!("an altered obligation must block source access"),
            ),
            3 => upload.finish(&mut tree, TimestampNs(4)).map(|_| ()),
            4 => upload.cancel(&mut tree, TimestampNs(4)).map(|_| ()),
            5 => upload.reconcile(&mut tree, TimestampNs(4)).map(|_| ()),
            _ => unreachable!(),
        };
        assert!(matches!(result, Err(UploaderError::Authority(_))));
        assert_eq!(store.borrow().calls, calls);
        assert_eq!(upload.phase(), phase);
        assert_eq!(*upload.budget().consumed(), consumed);
        let node = tree.get(&region)?;
        assert_eq!(node.state, RegionState::Active);
        assert_eq!(
            node.obligations[&obligation].state,
            ObligationState::Verified
        );
        assert_eq!(
            node.obligations[&obligation].proof_digest,
            Some(unrelated_proof)
        );
        assert!(node.quiescence_proof.is_none());
    }
    emit("exact-obligation-before-every-boundary", 6);
    Ok(())
}

#[test]
fn terminal_receipts_survive_blocked_finalization_without_repeat_or_false_refund() -> Test {
    for completed in [true, false] {
        let (_root_owner, mut parent, mut tree) = property()?;
        let mut transport = MemoryTransport::default();
        let store = transport.store.clone();
        let before = parent.budget().remaining();
        let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
        upload.upload_chunks(&tree, || TimestampNs(2), |_| b"abc".to_vec())?;
        let region = upload.region().clone();
        let obligation = upload.obligation().clone();
        let task = TaskId::new("task:owned-upload-finalizer")?;
        tree.register_task(&region, task.clone(), TimestampNs(2))?;
        let result = if completed {
            upload.finish(&mut tree, TimestampNs(3)).map(|_| ())
        } else {
            upload.cancel(&mut tree, TimestampNs(3)).map(|_| ())
        };
        assert!(matches!(result, Err(UploaderError::Authority(_))));
        let phase = if completed {
            MultipartPhase::Completed
        } else {
            MultipartPhase::Aborted
        };
        let terminal = if completed {
            ObligationState::Verified
        } else {
            ObligationState::Cancelled
        };
        assert_eq!(upload.phase(), phase);
        let node = tree.get(&region)?;
        assert_eq!(node.state, RegionState::Draining);
        assert_eq!(node.obligations[&obligation].state, terminal);
        let proof = node.obligations[&obligation]
            .proof_digest
            .ok_or("terminal receipt proof missing")?;
        assert!(node.quiescence_proof.is_none());
        let consumed = *upload.budget().consumed();
        let calls = store.borrow().calls.clone();
        assert_eq!(calls.len(), 3);
        assert!(upload.finish(&mut tree, TimestampNs(4)).is_err());
        assert!(upload.cancel(&mut tree, TimestampNs(4)).is_err());
        assert!(
            upload
                .settle_indeterminate(
                    &mut tree,
                    TimestampNs(4),
                    "a known provider outcome cannot become unknown",
                    ContentDigest::sha256(b"follow-up reference"),
                )
                .is_err()
        );
        assert_eq!(store.borrow().calls, calls);
        assert_eq!(*upload.budget().consumed(), consumed);
        tree.complete_task(&region, &task, TaskOutcome::Success, TimestampNs(5))?;
        let retried_proof = if completed {
            let receipt = upload.finish(&mut tree, TimestampNs(6))?;
            assert_eq!(upload.finish(&mut tree, TimestampNs(7))?, receipt);
            receipt.digest()
        } else {
            let receipt = upload.cancel(&mut tree, TimestampNs(6))?;
            assert_eq!(upload.cancel(&mut tree, TimestampNs(7))?, receipt);
            receipt.digest()
        };
        assert_eq!(retried_proof, proof);
        assert_eq!(store.borrow().calls, calls);
        let node = tree.get(&region)?;
        assert_eq!(node.state, RegionState::Closed);
        assert_eq!(node.obligations[&obligation].state, terminal);
        assert_eq!(node.obligations[&obligation].proof_digest, Some(proof));
        assert_eq!(
            node.quiescence_proof
                .as_ref()
                .ok_or("missing closure proof")?
                .total_tasks,
            1
        );
        drop(upload);
        assert_eq!(
            before.bytes - parent.budget().remaining().bytes,
            consumed.bytes
        );
        assert_eq!(
            before.storage_operations - parent.budget().remaining().storage_operations,
            consumed.storage_operations
        );
    }
    emit("terminal-receipt-retained-through-local-drain", 2);
    Ok(())
}

fn assert_indeterminate_owner_cannot_resume_work(
    upload: &mut StagedUpload<'_, MemoryTransport>,
    tree: &mut fss_core::RegionTree,
    now: TimestampNs,
) {
    assert!(upload.start(tree, now).is_err());
    assert!(upload.upload_part(tree, now, 0, b"abc").is_err());
    assert!(
        upload
            .upload_chunks(
                tree,
                || now,
                |_| panic!("locally settled uncertainty cannot reread source data"),
            )
            .is_err()
    );
    assert!(upload.finish(tree, now).is_err());
    assert!(upload.cancel(tree, now).is_err());
    assert!(upload.reconcile(tree, now).is_err());
}

#[test]
fn exhausted_unknown_recovery_can_close_only_with_explicit_indeterminate_evidence() -> Test {
    let (root_owner, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let before = parent.budget().remaining();
    let allowance = minimum_upload_budget(3, policy())?;
    let mut upload = StagedUpload::stage(
        &mut parent,
        &mut tree,
        &mut transport,
        OperationId::parse("operation:upload")?,
        3,
        policy(),
        root(),
        spec("operation:upload", allowance)?,
        RESOURCE,
        TimestampNs(1),
    )?;
    let region = upload.region().clone();
    let obligation = upload.obligation().clone();
    let intent = upload.intent().digest();
    store.borrow_mut().fault_once = Some(TransportOperation::Initiate);
    assert!(upload.start(&tree, TimestampNs(2)).is_err());
    store.borrow_mut().unknown = true;
    let uncertain = MultipartPhase::Uncertain(TransportOperation::Initiate);
    for now in 3..=7 {
        assert_eq!(upload.reconcile(&mut tree, TimestampNs(now))?, uncertain);
    }
    assert_eq!(upload.budget().remaining().storage_operations, 0);
    let calls = store.borrow().calls.clone();
    assert_eq!(calls.len(), 6);
    assert!(upload.reconcile(&mut tree, TimestampNs(8)).is_err());
    assert_eq!(store.borrow().calls, calls);
    assert_eq!(
        tree.get(&region)?.obligations[&obligation].state,
        ObligationState::Pending
    );

    let note = "provider outcome unavailable; inspect the retained upload intent";
    let reference = ContentDigest::sha256(b"owned reconciliation follow-up record");
    let consumed = *upload.budget().consumed();
    let receipt = upload.settle_indeterminate(&mut tree, TimestampNs(9), note, reference)?;
    assert_eq!(receipt.intent_digest(), intent);
    assert_eq!(receipt.region(), &region);
    assert_eq!(receipt.obligation(), &obligation);
    assert_eq!(receipt.operation(), TransportOperation::Initiate);
    assert_eq!(receipt.reconciliation_reference(), reference);
    assert!(receipt.note().contains(note));
    assert_eq!(upload.phase(), uncertain);
    let node = tree.get(&region)?;
    assert_eq!(node.state, RegionState::Closed);
    assert_eq!(
        node.obligations[&obligation].state,
        ObligationState::Indeterminate
    );
    assert_eq!(
        node.obligations[&obligation].proof_digest,
        Some(receipt.digest())
    );
    assert_eq!(node.reconciliation_obligations[&obligation], receipt.note());
    assert_eq!(
        node.quiescence_proof
            .as_ref()
            .ok_or("missing closure proof")?
            .indeterminate_obligations,
        1
    );
    assert_eq!(
        upload.settle_indeterminate(&mut tree, TimestampNs(10), note, reference)?,
        receipt
    );
    assert!(
        upload
            .settle_indeterminate(&mut tree, TimestampNs(11), "different follow-up", reference)
            .is_err()
    );
    assert!(
        upload
            .settle_indeterminate(
                &mut tree,
                TimestampNs(11),
                note,
                ContentDigest::sha256(b"different reconciliation record"),
            )
            .is_err()
    );
    assert_indeterminate_owner_cannot_resume_work(&mut upload, &mut tree, TimestampNs(11));
    assert_eq!(store.borrow().calls, calls);
    assert_eq!(*upload.budget().consumed(), consumed);
    drop(upload);
    assert_eq!(parent.budget().remaining().bytes, before.bytes);
    assert_eq!(
        before.storage_operations - parent.budget().remaining().storage_operations,
        consumed.storage_operations
    );
    root_owner.request_cancellation(&mut tree, TimestampNs(12))?;
    parent.begin_drain(&mut tree, TimestampNs(12))?;
    assert_eq!(
        parent
            .finalize(&mut tree, TimestampNs(12))?
            .indeterminate_obligations,
        1
    );
    emit("exhausted-recovery-explicit-indeterminate-closure", 8);
    Ok(())
}

#[test]
fn indeterminate_receipt_survives_local_drain_and_binds_every_retry() -> Test {
    let (_root_owner, mut parent, mut tree) = property()?;
    let (_other_root, _other_parent, mut wrong_tree) = property()?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let before = parent.budget().remaining();
    let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
    upload.start(&tree, TimestampNs(2))?;
    let region = upload.region().clone();
    let obligation = upload.obligation().clone();
    let task = TaskId::new("task:uncertain-upload-drain")?;
    tree.register_task(&region, task.clone(), TimestampNs(2))?;
    store.borrow_mut().fault_once = Some(TransportOperation::UploadPart);
    assert!(
        upload
            .upload_part(&tree, TimestampNs(3), 0, b"abc")
            .is_err()
    );
    let calls = store.borrow().calls.clone();
    let consumed = *upload.budget().consumed();
    let note = "part ACK lost; retained follow-up owns provider inventory inspection";
    let reference = ContentDigest::sha256(b"pending part inspection");
    assert!(matches!(
        upload.settle_indeterminate(&mut tree, TimestampNs(4), note, reference),
        Err(UploaderError::Authority(_))
    ));
    let node = tree.get(&region)?;
    assert_eq!(node.state, RegionState::Draining);
    assert!(node.quiescence_proof.is_none());
    assert_eq!(
        node.obligations[&obligation].state,
        ObligationState::Indeterminate
    );
    let proof = node.obligations[&obligation]
        .proof_digest
        .ok_or("missing unresolved proof")?;
    let recorded_note = node.reconciliation_obligations[&obligation].clone();
    let retained = upload
        .indeterminate_receipt()
        .ok_or("missing retained recovery receipt")?
        .clone();
    assert_eq!(retained.digest(), proof);
    assert_eq!(retained.note(), recorded_note);
    assert!(
        upload
            .settle_indeterminate(&mut wrong_tree, TimestampNs(5), note, reference)
            .is_err()
    );
    assert!(
        upload
            .settle_indeterminate(&mut tree, TimestampNs(5), "different follow-up", reference)
            .is_err()
    );
    assert!(
        upload
            .settle_indeterminate(
                &mut tree,
                TimestampNs(5),
                note,
                ContentDigest::sha256(b"another follow-up"),
            )
            .is_err()
    );
    assert!(
        upload
            .settle_indeterminate(&mut tree, TimestampNs(5), note, reference)
            .is_err()
    );
    assert_indeterminate_owner_cannot_resume_work(&mut upload, &mut tree, TimestampNs(6));
    assert_eq!(
        tree.get(&region)?.obligations[&obligation].proof_digest,
        Some(proof)
    );
    assert_eq!(
        tree.get(&region)?.reconciliation_obligations[&obligation],
        recorded_note
    );
    assert_eq!(store.borrow().calls, calls);
    tree.complete_task(&region, &task, TaskOutcome::Cancelled, TimestampNs(7))?;
    let receipt = upload.settle_indeterminate(&mut tree, TimestampNs(8), note, reference)?;
    assert_eq!(receipt, retained);
    assert_eq!(receipt.digest(), proof);
    assert_eq!(receipt.note(), recorded_note);
    assert_eq!(receipt.operation(), TransportOperation::UploadPart);
    assert_eq!(
        upload.phase(),
        MultipartPhase::Uncertain(TransportOperation::UploadPart)
    );
    assert_eq!(
        upload.settle_indeterminate(&mut tree, TimestampNs(9), note, reference)?,
        receipt
    );
    assert_eq!(tree.get(&region)?.state, RegionState::Closed);
    assert_eq!(store.borrow().calls, calls);
    assert_eq!(*upload.budget().consumed(), consumed);
    drop(upload);
    assert_eq!(
        before.bytes - parent.budget().remaining().bytes,
        consumed.bytes
    );
    assert_eq!(
        before.storage_operations - parent.budget().remaining().storage_operations,
        consumed.storage_operations
    );
    emit("indeterminate-retry-retains-proof-note-and-reservation", 7);
    Ok(())
}

#[test]
fn invalid_indeterminate_settlement_preserves_exact_pending_ownership() -> Test {
    let (_root_owner, mut parent, mut tree) = property()?;
    let (_other_root, _other_parent, mut wrong_tree) = property()?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
    let region = upload.region().clone();
    let obligation = upload.obligation().clone();
    let reference = ContentDigest::sha256(b"owned follow-up");
    let note = "retain uncertainty for provider inspection";
    assert!(
        upload
            .settle_indeterminate(&mut tree, TimestampNs(1), note, reference)
            .is_err()
    );
    assert!(store.borrow().calls.is_empty());
    upload.start(&tree, TimestampNs(2))?;
    assert!(
        upload
            .settle_indeterminate(&mut tree, TimestampNs(2), note, reference)
            .is_err()
    );
    store.borrow_mut().fault_once = Some(TransportOperation::UploadPart);
    assert!(
        upload
            .upload_part(&tree, TimestampNs(3), 0, b"abc")
            .is_err()
    );
    let calls = store.borrow().calls.clone();
    let consumed = *upload.budget().consumed();
    for invalid in [
        String::new(),
        "   ".into(),
        "line\nbreak".into(),
        "x".repeat(257),
        "é".repeat(129),
    ] {
        assert!(
            upload
                .settle_indeterminate(&mut tree, TimestampNs(4), &invalid, reference)
                .is_err()
        );
    }
    for invalid in [
        ContentDigest::new(DigestAlgorithm::Sha256, [0; 32]),
        ContentDigest::new(DigestAlgorithm::Blake3, [1; 32]),
    ] {
        assert!(
            upload
                .settle_indeterminate(&mut tree, TimestampNs(4), note, invalid)
                .is_err()
        );
    }
    assert!(
        upload
            .settle_indeterminate(&mut wrong_tree, TimestampNs(4), note, reference)
            .is_err()
    );
    assert!(
        upload
            .settle_indeterminate(&mut tree, TimestampNs(2), note, reference)
            .is_err()
    );
    let unrelated = ContentDigest::sha256(b"independently settled obligation");
    let node = tree.get(&region)?;
    assert_eq!(node.state, RegionState::Active);
    assert_eq!(
        node.obligations[&obligation].state,
        ObligationState::Pending
    );
    assert_eq!(node.obligations[&obligation].proof_digest, None);
    assert!(node.reconciliation_obligations.is_empty());
    assert!(node.quiescence_proof.is_none());
    tree.resolve_obligation(
        &region,
        &obligation,
        ObligationState::Verified,
        Some(unrelated),
        None,
    )?;
    assert!(
        upload
            .settle_indeterminate(&mut tree, TimestampNs(4), note, reference)
            .is_err()
    );
    assert_eq!(
        tree.get(&region)?.obligations[&obligation].proof_digest,
        Some(unrelated)
    );
    assert_eq!(store.borrow().calls, calls);
    assert_eq!(*upload.budget().consumed(), consumed);
    assert_eq!(
        upload.phase(),
        MultipartPhase::Uncertain(TransportOperation::UploadPart)
    );
    emit("invalid-unknown-settlement-is-atomic", 12);
    Ok(())
}

#[test]
fn backdated_preparation_cannot_reserve_budget_or_attach_an_owner() -> Test {
    let (mut root_owner, mut tree) = fss_runtime::authority::AuthorityCx::root(
        spec("operation:root", budget())?,
        fss_core::RegionId::new("region:process")?,
        fss_core::RegionKind::Process,
        budget(),
        TimestampNs(0),
    )?;
    let mut parent = root_owner.scope_down(
        &mut tree,
        fss_core::RegionId::new("region:property")?,
        fss_core::RegionKind::Property,
        budget(),
        spec("operation:property", budget())?,
        TimestampNs(10),
    )?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let before = parent.budget().remaining();
    let regions = tree.region_count();
    assert!(matches!(
        StagedUpload::stage(
            &mut parent,
            &mut tree,
            &mut transport,
            OperationId::parse("operation:upload")?,
            3,
            policy(),
            root(),
            spec("operation:upload", budget())?,
            RESOURCE,
            TimestampNs(9),
        ),
        Err(UploaderError::Protocol(MultipartError::ClockRegression))
    ));
    assert_eq!(parent.budget().remaining(), before);
    assert_eq!(tree.region_count(), regions);
    assert!(store.borrow().calls.is_empty());
    emit("parent-lifetime-preflight-is-atomic", 3);
    Ok(())
}

#[test]
fn source_access_clock_cannot_regress_before_part_dispatch() -> Test {
    let (_root_owner, mut parent, mut tree) = property()?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let mut upload = stage(&mut parent, &mut tree, &mut transport)?;
    let mut times = [TimestampNs(2), TimestampNs(4), TimestampNs(3)].into_iter();
    let mut reads = 0;
    assert!(matches!(
        upload.upload_chunks(
            &tree,
            || times.next().expect("three bounded clock samples"),
            |index| {
                assert_eq!(index, 0);
                reads += 1;
                b"abc".to_vec()
            },
        ),
        Err(UploaderError::Protocol(MultipartError::ClockRegression))
    ));
    assert_eq!(reads, 1);
    assert_eq!(store.borrow().calls, vec![TransportOperation::Initiate]);
    assert_eq!(upload.confirmed_parts(), 0);
    assert_eq!(upload.budget().consumed().bytes, 0);
    assert_eq!(upload.phase(), MultipartPhase::Uploading);
    assert_eq!(
        tree.get(upload.region())?.obligations[upload.obligation()].state,
        ObligationState::Pending
    );
    upload.cancel(&mut tree, TimestampNs(5))?;
    assert_eq!(
        store.borrow().calls,
        vec![TransportOperation::Initiate, TransportOperation::Abort]
    );
    emit("source-clock-bound-before-part-io", 5);
    Ok(())
}

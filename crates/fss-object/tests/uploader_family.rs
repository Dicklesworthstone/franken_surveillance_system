#![forbid(unsafe_code)]
//! Owned-upload regressions: runtime authority, cancellation, budgets and uncertain I/O.

mod multipart_support;

use std::collections::BTreeSet;

use fss_core::{
    BudgetVector, ContentDigest, ObligationState, OperationId, RegionState, RuntimeGrant,
    TimestampNs,
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

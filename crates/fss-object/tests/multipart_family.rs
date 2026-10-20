#![forbid(unsafe_code)]
//! Protocol regressions exercise real scoped authority and an injected fault store.

mod multipart_support;

use fss_core::{ContentDigest, OperationId, RegionId, RegionKind, RegionTree, TimestampNs};
use fss_object::multipart::{
    MultipartError, MultipartPhase, MultipartSession, ProviderUploadState, Reconciliation,
    TransportOperation, UploadId, UploadIo,
};
use fss_object::planner::{ChunkPlan, ChunkPolicy, MIN_PART_SIZE, plan_chunks};
use fss_runtime::authority::AuthorityCx;
use multipart_support::{MemoryTransport, RESOURCE, Test, budget, property, spec};

struct Owner {
    _root: AuthorityCx,
    _property: AuthorityCx,
    child: AuthorityCx,
    tree: RegionTree,
}
impl Owner {
    fn new(deadline: Option<TimestampNs>) -> Result<Self, Box<dyn std::error::Error>> {
        let (root, mut property, mut tree) = property()?;
        let mut child_spec = spec("operation:multipart", budget())?;
        child_spec.deadline = deadline;
        let child = property.scope_down(
            &mut tree,
            RegionId::new("region:store")?,
            RegionKind::ObjectStore,
            budget(),
            child_spec,
            TimestampNs(0),
        )?;
        Ok(Self {
            _root: root,
            _property: property,
            child,
            tree,
        })
    }
    fn io(&mut self, now: i128) -> UploadIo<'_> {
        UploadIo {
            authority: &mut self.child,
            tree: &self.tree,
            now: TimestampNs(now),
        }
    }
}
fn plan() -> Result<ChunkPlan, Box<dyn std::error::Error>> {
    Ok(plan_chunks(
        3,
        ChunkPolicy {
            part_size: MIN_PART_SIZE,
        },
    )?)
}
fn root() -> ContentDigest {
    ContentDigest::sha256(b"root")
}
fn prepare<'a>(
    transport: &'a mut MemoryTransport,
    plan: &ChunkPlan,
) -> Result<MultipartSession<'a, MemoryTransport>, Box<dyn std::error::Error>> {
    Ok(MultipartSession::prepare(
        transport,
        plan,
        root(),
        OperationId::parse("operation:multipart")?,
        RESOURCE,
        TimestampNs(0),
    )?)
}
fn emit(property: &str, cases: usize) {
    println!(
        "{{\"family\":\"FSS-130\",\"property\":\"{property}\",\"cases\":{cases},\"verdict\":\"pass\"}}"
    );
}

#[test]
fn opaque_etag_is_independent_of_verified_part_digest() -> Test {
    let mut owner = Owner::new(None)?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let plan = plan()?;
    let mut session = prepare(&mut transport, &plan)?;
    assert!(
        store.borrow().calls.is_empty(),
        "preparation has no external effect"
    );
    session.start(owner.io(1))?;
    let part = session.upload_part(owner.io(2), &plan, 0, b"abc")?;
    assert_ne!(part.etag.0, part.content_digest.to_text());
    assert_eq!(part.content_digest, ContentDigest::sha256(b"abc"));
    let receipt = session.complete(owner.io(3), &plan, root())?;
    assert_eq!(receipt.parts, vec![part]);
    assert_eq!(receipt.intent_digest, session.intent().digest());
    assert_eq!(receipt, session.complete(owner.io(4), &plan, root())?);
    assert_eq!(
        store.borrow().calls.len(),
        3,
        "terminal replay performs no duplicate I/O"
    );
    assert!(matches!(
        session.upload_part(owner.io(4), &plan, 0, b"abc"),
        Err(MultipartError::WrongState { .. })
    ));
    emit("opaque-etag-root-last", 5);
    Ok(())
}

#[test]
fn same_length_replay_conflict_is_checked_without_duplicate_traffic() -> Test {
    let mut owner = Owner::new(None)?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let plan = plan()?;
    let mut session = prepare(&mut transport, &plan)?;
    session.start(owner.io(1))?;
    let first = session.upload_part(owner.io(2), &plan, 0, b"abc")?;
    assert_eq!(session.upload_part(owner.io(3), &plan, 0, b"abc")?, first);
    assert!(matches!(
        session.upload_part(owner.io(3), &plan, 0, b"abd"),
        Err(MultipartError::PartConflict { index: 0 })
    ));
    assert!(matches!(
        session.upload_part(owner.io(3), &plan, 0, b"ab"),
        Err(MultipartError::PartConflict { index: 0 })
    ));
    assert!(matches!(
        session.upload_part(owner.io(3), &plan, u64::MAX, b"abc"),
        Err(MultipartError::UnknownPart { .. })
    ));
    assert_eq!(session.confirmed_parts(), 1);
    assert_eq!(store.borrow().calls.len(), 2);
    emit("idempotent-replay-conflict", 5);
    Ok(())
}

#[test]
fn exact_plan_root_and_cost_rows_are_bound_before_any_publication() -> Test {
    let mut owner = Owner::new(None)?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let plan = plan()?;
    let mut forged = plan.clone();
    forged.wire_bytes += 1;
    assert!(matches!(
        MultipartSession::prepare(
            &mut transport,
            &forged,
            root(),
            OperationId::parse("operation:multipart")?,
            RESOURCE,
            TimestampNs(0)
        ),
        Err(MultipartError::InvalidIntent)
    ));
    let mut session = prepare(&mut transport, &plan)?;
    session.start(owner.io(1))?;
    assert!(matches!(
        session.complete(owner.io(2), &plan, root()),
        Err(MultipartError::Incomplete {
            confirmed: 0,
            required: 1
        })
    ));
    session.upload_part(owner.io(2), &plan, 0, b"abc")?;
    assert!(matches!(
        session.complete(owner.io(3), &plan, ContentDigest::sha256(b"other-root")),
        Err(MultipartError::StaleRoot { .. })
    ));
    assert!(matches!(
        session.complete(owner.io(3), &forged, root()),
        Err(MultipartError::StalePlan { .. })
    ));
    assert_eq!(store.borrow().calls.len(), 2);
    session.complete(owner.io(3), &plan, root())?;
    emit("exact-plan-root-and-costs", 4);
    Ok(())
}

#[test]
fn lost_ack_at_every_dispatch_retains_owner_until_reconciliation() -> Test {
    for fault in [
        TransportOperation::Initiate,
        TransportOperation::UploadPart,
        TransportOperation::Complete,
        TransportOperation::Abort,
    ] {
        let mut owner = Owner::new(None)?;
        let mut transport = MemoryTransport::default();
        let store = transport.store.clone();
        let plan = plan()?;
        let mut session = prepare(&mut transport, &plan)?;
        if fault != TransportOperation::Initiate {
            session.start(owner.io(1))?;
        }
        if matches!(
            fault,
            TransportOperation::Complete | TransportOperation::Abort
        ) {
            session.upload_part(owner.io(2), &plan, 0, b"abc")?;
        }
        store.borrow_mut().fault_once = Some(fault);
        let outcome = match fault {
            TransportOperation::Initiate => session.start(owner.io(3)).map(|_| ()),
            TransportOperation::UploadPart => session
                .upload_part(owner.io(3), &plan, 0, b"abc")
                .map(|_| ()),
            TransportOperation::Complete => {
                session.complete(owner.io(3), &plan, root()).map(|_| ())
            }
            TransportOperation::Abort => session.abort(owner.io(3)).map(|_| ()),
            TransportOperation::Reconcile => unreachable!(),
        };
        assert!(matches!(outcome, Err(MultipartError::Transport { .. })));
        assert_eq!(session.phase(), MultipartPhase::Uncertain(fault));
        let calls = store.borrow().calls.len();
        assert!(matches!(
            session.abort(owner.io(4)),
            Err(MultipartError::RequiresReconciliation { .. })
        ));
        assert_eq!(
            store.borrow().calls.len(),
            calls,
            "no blind abort after uncertain dispatch"
        );
        store.borrow_mut().unknown = true;
        assert_eq!(
            session.reconcile(owner.io(4))?,
            MultipartPhase::Uncertain(fault)
        );
        store.borrow_mut().unknown = false;
        let expected = match fault {
            TransportOperation::Complete => MultipartPhase::Completed,
            TransportOperation::Abort => MultipartPhase::Aborted,
            _ => MultipartPhase::Uploading,
        };
        assert_eq!(session.reconcile(owner.io(5))?, expected);
        assert_eq!(
            store
                .borrow()
                .calls
                .iter()
                .filter(|op| **op == fault)
                .count(),
            1
        );
        if fault == TransportOperation::UploadPart {
            assert_eq!(session.confirmed_parts(), 1);
            assert!(matches!(
                session.upload_part(owner.io(6), &plan, 0, b"xyz"),
                Err(MultipartError::PartConflict { .. })
            ));
        }
    }
    emit("lost-ack-reconciliation", 4);
    Ok(())
}

#[test]
fn negative_initiation_observation_permits_only_same_intent_retry() -> Test {
    let mut owner = Owner::new(None)?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    store.borrow_mut().fault_once = Some(TransportOperation::Initiate);
    store.borrow_mut().fail_before_effect = true;
    let plan = plan()?;
    let mut session = prepare(&mut transport, &plan)?;
    let intent = session.intent().digest();
    assert!(session.start(owner.io(1)).is_err());
    store.borrow_mut().fault_once = Some(TransportOperation::Reconcile);
    assert!(session.reconcile(owner.io(2)).is_err());
    assert_eq!(
        session.phase(),
        MultipartPhase::Uncertain(TransportOperation::Initiate)
    );
    assert_eq!(session.reconcile(owner.io(3))?, MultipartPhase::Prepared);
    session.start(owner.io(4))?;
    assert_eq!(session.intent().digest(), intent);
    assert_eq!(
        store.borrow().intent.as_ref().map(|value| value.digest()),
        Some(intent)
    );
    emit("initiation-identity-survives-retry", 3);
    Ok(())
}

#[test]
fn corrupt_part_ack_requires_a_valid_independent_readback() -> Test {
    let mut owner = Owner::new(None)?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let plan = plan()?;
    let mut session = prepare(&mut transport, &plan)?;
    session.start(owner.io(1))?;
    store.borrow_mut().wrong_checksum_once = true;
    assert!(matches!(
        session.upload_part(owner.io(2), &plan, 0, b"abc"),
        Err(MultipartError::InvalidPartReceipt { index: 0 })
    ));
    assert_eq!(session.confirmed_parts(), 0);
    assert_eq!(
        session.phase(),
        MultipartPhase::Uncertain(TransportOperation::UploadPart)
    );
    session.reconcile(owner.io(3))?;
    assert_eq!(session.confirmed_parts(), 1);
    session.complete(owner.io(4), &plan, root())?;
    emit("independent-part-checksum", 2);
    Ok(())
}

#[test]
fn forged_or_partial_completion_observations_never_upgrade_uncertainty() -> Test {
    let mut owner = Owner::new(None)?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let plan = plan()?;
    let mut session = prepare(&mut transport, &plan)?;
    session.start(owner.io(1))?;
    let part = session.upload_part(owner.io(2), &plan, 0, b"abc")?;
    store.borrow_mut().fault_once = Some(TransportOperation::Complete);
    assert!(session.complete(owner.io(3), &plan, root()).is_err());
    for (intent, manifest_root, upload, parts) in [
        (
            ContentDigest::sha256(b"wrong-intent"),
            root(),
            "provider-upload-0",
            vec![part.clone()],
        ),
        (
            session.intent().digest(),
            ContentDigest::sha256(b"wrong-root"),
            "provider-upload-0",
            vec![part.clone()],
        ),
        (
            session.intent().digest(),
            root(),
            "unrelated-upload",
            vec![part.clone()],
        ),
        (
            session.intent().digest(),
            root(),
            "provider-upload-0",
            Vec::new(),
        ),
        (
            session.intent().digest(),
            root(),
            "provider-upload-0",
            vec![part.clone(), part.clone()],
        ),
    ] {
        store.borrow_mut().observation = Some(Reconciliation {
            intent_digest: intent,
            state: ProviderUploadState::Completed {
                upload: UploadId(upload.into()),
                manifest_root,
                parts,
            },
        });
        assert_eq!(
            session.reconcile(owner.io(4)),
            Err(MultipartError::ReconciliationMismatch)
        );
        assert_eq!(
            session.phase(),
            MultipartPhase::Uncertain(TransportOperation::Complete)
        );
    }
    store.borrow_mut().observation = None;
    assert_eq!(session.reconcile(owner.io(5))?, MultipartPhase::Completed);
    emit("forged-partial-observation-refused", 5);
    Ok(())
}

#[test]
fn mismatched_tree_owner_deadline_and_clock_refuse_before_io() -> Test {
    let mut owner = Owner::new(Some(TimestampNs(10)))?;
    let mut other = Owner::new(None)?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let plan = plan()?;
    let mut session = prepare(&mut transport, &plan)?;
    session.start(owner.io(5))?;
    assert!(matches!(
        session.upload_part(
            UploadIo {
                authority: &mut owner.child,
                tree: &other.tree,
                now: TimestampNs(6)
            },
            &plan,
            0,
            b"abc"
        ),
        Err(MultipartError::Authority(_))
    ));
    assert_eq!(
        session.upload_part(other.io(6), &plan, 0, b"abc"),
        Err(MultipartError::OwnerMismatch)
    );
    assert_eq!(
        session.upload_part(owner.io(4), &plan, 0, b"abc"),
        Err(MultipartError::ClockRegression)
    );
    assert_eq!(
        session.upload_part(owner.io(10), &plan, 0, b"abc"),
        Err(MultipartError::Deadline)
    );
    assert_eq!(store.borrow().calls.len(), 1);
    session.abort(owner.io(10))?;
    emit("authority-time-binding", 5);
    Ok(())
}

#[test]
fn out_of_order_parts_complete_only_with_the_entire_canonical_inventory() -> Test {
    let mut owner = Owner::new(None)?;
    let mut transport = MemoryTransport::default();
    let store = transport.store.clone();
    let plan = plan_chunks(
        2 * MIN_PART_SIZE + 3,
        ChunkPolicy {
            part_size: MIN_PART_SIZE,
        },
    )?;
    let mut session = prepare(&mut transport, &plan)?;
    session.start(owner.io(1))?;
    session.upload_part(owner.io(2), &plan, 2, b"end")?;
    session.upload_part(owner.io(3), &plan, 0, &vec![1; MIN_PART_SIZE as usize])?;
    assert_eq!(
        session.complete(owner.io(4), &plan, root()),
        Err(MultipartError::Incomplete {
            confirmed: 2,
            required: 3
        })
    );
    assert!(!store.borrow().calls.contains(&TransportOperation::Complete));
    session.upload_part(owner.io(5), &plan, 1, &vec![2; MIN_PART_SIZE as usize])?;
    let receipt = session.complete(owner.io(6), &plan, root())?;
    assert_eq!(
        receipt
            .parts
            .iter()
            .map(|part| part.index)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert_eq!(
        receipt.parts[2].content_digest,
        ContentDigest::sha256(b"end")
    );
    assert_eq!(owner.child.budget().consumed().bytes, plan.object_bytes);
    emit("out-of-order-complete-inventory", 5);
    Ok(())
}

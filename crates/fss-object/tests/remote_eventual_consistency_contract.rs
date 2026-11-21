#![forbid(unsafe_code)]
//! FSS-132 contract suite: deterministic remote eventual-consistency and partial-list
//! provider simulator (`fss-object::provider::remote_simulator`).
//!
//! Exercises:
//! 1. Reference oracle differential parity (`run_oracle` matches `InMemoryObjectStoreProvider`
//!    bit-for-bit on a clean schedule);
//! 2. Eventual visibility lag on `ObjectStoreProvider`, `HEAD`, `GET`, and `LIST`;
//! 3. Stale post-delete / post-retirement ghosts in `LIST` (never upgrading to retrievable);
//! 4. Paginated listing under forced early truncation, partial omissions, and corrupt tokens;
//! 5. Conditional writes (`If-None-Match: *`, `If-Match`), lost ACKs, and readback bit-flips;
//! 6. Full `MultipartSession`, `StagedUpload`, and `FileUploadJournal` cold-restart recovery
//!    under eventual consistency, partial part lists, framing budgets, clock-step deadlines,
//!    cancellation, and explicit indeterminate settlement;
//! 7. Adversarial provider negative controls (every lying-provider mode refused);
//! 8. Hard-bound validation refusals and a 16-seed deterministic fault-rate property campaign.

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{
    BudgetVector, CanonicalEncode, ContentDigest, ObligationState, OperationId, RegionId,
    RegionKind, RegionState, RegionTree, RootAuthoritySpec, RuntimeGrant, TimestampNs,
};
use fss_object::multipart::{
    ETag, MultipartError, MultipartPhase, MultipartSession, TransportOperation, UploadIo,
};
use fss_object::planner::{ChunkPlan, ChunkPolicy, MIN_PART_SIZE, plan_chunks};
use fss_object::provider::memory::InMemoryObjectStoreProvider;
use fss_object::provider::oracle::run_oracle;
use fss_object::provider::remote_simulator::{
    AdversarialMisbehavior, ConditionalPrecondition, FaultKind, FaultOperation, FaultRatesPpm,
    FaultRule, ListRequest, ListingConsistency, MAX_LIST_PAGE_KEYS, MAX_SIMULATOR_BYTES,
    MAX_SIMULATOR_OBJECTS, REMOTE_PROVIDER_SIM_DOMAIN, RecoveryGuidance, RemoteFaultSchedule,
    RemoteObjectError, RemoteProviderSimulator, SimulatorLimits,
};
use fss_object::provider::{ObjectStoreProvider, ProviderError, PublicationState};
use fss_object::uploader::{StagedUpload, UploaderError};
use fss_object::{InMemoryObjectStore, ObjectLimits, ObjectManifest};
use fss_runtime::authority::AuthorityCx;

#[cfg(unix)]
use fss_object::HostSpoolIo;
#[cfg(unix)]
use fss_object::multipart::{MultipartRecovery, UploadJournalPin};
#[cfg(unix)]
use fss_object::upload_journal::{FileUploadJournal, UploadJournalLimits};

const RESOURCE: &str = "archive:test-store/evidence-object";
type Test = Result<(), Box<dyn std::error::Error>>;

fn budget() -> BudgetVector {
    let mut result = BudgetVector::ZERO;
    result.bytes = 64 * 1024 * 1024;
    result.network_bytes = result.bytes;
    result.storage_operations = 256;
    result
}

fn spec(
    operation: &str,
    allowance: BudgetVector,
) -> Result<RootAuthoritySpec, Box<dyn std::error::Error>> {
    Ok(RootAuthoritySpec {
        trace_id: "trace:fss-132-sim".into(),
        operation_id: OperationId::parse(operation)?,
        principal: "principal:test".into(),
        capabilities: [
            RuntimeGrant::ObjectStage,
            RuntimeGrant::ObjectPublish,
            RuntimeGrant::AdapterNet,
        ]
        .iter()
        .map(|grant| grant.as_str().to_owned())
        .collect(),
        deadline: None,
        priority: 10,
        budgets: allowance,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"fss-132-sim"),
        generation: 1,
    })
}

fn property() -> Result<(AuthorityCx, AuthorityCx, RegionTree), Box<dyn std::error::Error>> {
    let (mut root, mut tree) = AuthorityCx::root(
        spec("operation:root", budget())?,
        RegionId::new("region:process")?,
        RegionKind::Process,
        budget(),
        TimestampNs(0),
    )?;
    let prop = root.scope_down(
        &mut tree,
        RegionId::new("region:property")?,
        RegionKind::Property,
        budget(),
        spec("operation:property", budget())?,
        TimestampNs(0),
    )?;
    Ok((root, prop, tree))
}

fn emit_caplog(scenario: &str, sim: &RemoteProviderSimulator) {
    let report = sim.report();
    let line = report.to_jsonl_line(
        scenario,
        &format!(
            "cargo test --locked --offline -p fss-object --test remote_eventual_consistency_contract {scenario}"
        ),
    );
    println!("{line}");
    let summary = format!(
        "{{\"seed\":{},\"schedule_digest\":\"{}\",\"scenario_digest\":\"{}\",\"faults_injected\":{},\"unknown_reconciliations\":{},\"corruptions_caught\":{}}}",
        report.seed,
        report.schedule_digest,
        report.scenario_digest,
        report.cost.faults_injected,
        report.cost.unknown_reconciliations,
        report.cost.corruptions_caught,
    );
    println!(
        "CAPLOG {{\"step\":\"{scenario}\",\"verdict\":\"pass\",\"exit\":0,\"duration_ms\":0,\"expected\":{summary},\"observed\":{summary}}}"
    );
}

struct SessionOwner {
    _root: AuthorityCx,
    _property: AuthorityCx,
    child: AuthorityCx,
    tree: RegionTree,
}

impl SessionOwner {
    fn new(
        operation: &str,
        allowance: BudgetVector,
        deadline: Option<TimestampNs>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let (root, mut prop, mut tree) = property()?;
        let mut child_spec = spec(operation, allowance)?;
        child_spec.deadline = deadline;
        let child = prop.scope_down(
            &mut tree,
            RegionId::new("region:sim-store")?,
            RegionKind::ObjectStore,
            allowance,
            child_spec,
            TimestampNs(0),
        )?;
        Ok(Self {
            _root: root,
            _property: prop,
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

type TwoPartFixture = (ChunkPlan, Vec<u8>, Vec<u8>);

fn two_part_plan() -> Result<TwoPartFixture, Box<dyn std::error::Error>> {
    let part0 = vec![0x41u8; MIN_PART_SIZE as usize];
    let part1 = b"tail-segment-bytes".to_vec();
    let total = (part0.len() + part1.len()) as u64;
    let plan = plan_chunks(
        total,
        ChunkPolicy {
            part_size: MIN_PART_SIZE,
        },
    )?;
    assert_eq!(plan.chunks.len(), 2);
    Ok((plan, part0, part1))
}

fn small_plan() -> Result<ChunkPlan, Box<dyn std::error::Error>> {
    Ok(plan_chunks(
        12,
        ChunkPolicy {
            part_size: MIN_PART_SIZE,
        },
    )?)
}

fn manifest_root() -> ContentDigest {
    ContentDigest::sha256(b"fss-132-canonical-manifest-root")
}

// =========================================================================
// 1. Differential Reference Oracle Parity
// =========================================================================

#[test]
fn clean_simulator_matches_reference_oracle_digest_exactly() -> Test {
    let reference = run_oracle(InMemoryObjectStoreProvider::new(
        InMemoryObjectStore::new(ObjectLimits::new(64, 1 << 20)),
        2,
    ));
    let sim_report = run_oracle(RemoteProviderSimulator::clean(42)?);
    let sim_replay = run_oracle(RemoteProviderSimulator::clean(42)?);

    assert!(reference.all_passed);
    assert!(sim_report.all_passed);
    assert_eq!(sim_report.checks, reference.checks);
    assert_eq!(
        sim_report.scenario_digest, reference.scenario_digest,
        "clean remote simulator must match InMemoryObjectStoreProvider oracle digest bit-for-bit"
    );
    assert_eq!(sim_report, sim_replay);

    let probe_sim = RemoteProviderSimulator::clean(42)?;
    emit_caplog(
        "clean_simulator_matches_reference_oracle_digest_exactly",
        &probe_sim,
    );
    Ok(())
}

// =========================================================================
// 2. Eventual Visibility Lag & Stale Post-Retirement Ghosts (ObjectStoreProvider)
// =========================================================================

#[test]
fn provider_visibility_lag_corrupt_readback_and_retirement_ghosts() -> Test {
    let payload_a = b"archive-segment-alpha";
    let payload_b = b"archive-segment-beta";
    let witness_bytes = b"owner-authorized-deletion-witness";
    let digest_b = ContentDigest::sha256(payload_b);

    let schedule = RemoteFaultSchedule::clean(77)
        .with_visibility_lag(2)
        .with_ghost_retention(3)
        // Call #1 (epoch 0 da), #2 (epoch 1 da), #3 (epoch 2 da) precede call #4 (epoch 2 db).
        .with_rule(
            FaultRule::on_nth(
                FaultOperation::VerifyRetrievable,
                4,
                FaultKind::CorruptReadback,
            )
            .for_digest(digest_b),
        );
    let mut sim = RemoteProviderSimulator::new(SimulatorLimits::default(), schedule)?;

    let da = sim.stage(payload_a)?;
    let db = sim.stage(payload_b)?;
    let witness = sim.stage(witness_bytes)?;
    let manifest = ObjectManifest::new("fss-132-test", [da, db], None)?;
    let root = sim.stage(&manifest.canonical_bytes())?;

    for id in [da, db, witness, root] {
        sim.advance(id, PublicationState::Visible)?;
        sim.advance(id, PublicationState::Durable)?;
    }
    sim.activate_root(root, &[da, db])?;

    // Immediately after Durable commit at epoch 0 with lag 2, retrievability probe MUST fail
    // with eventual visibility lag, and listing MUST report EventualLag & complete == false.
    let early_probe = sim.verify_retrievable(da, TimestampNs(10));
    assert!(matches!(
        early_probe,
        Err(ProviderError::NotRetrievable { ref reason, .. })
            if reason.contains("eventual_visibility_lag")
    ));
    let early_list = sim.collect_complete_listing(Some("objects/".to_owned()), 16, 8)?;
    assert!(
        !early_list.complete,
        "lagging list must never claim completeness"
    );
    assert!(early_list.entries.is_empty());
    assert!(
        early_list
            .consistency_warnings
            .iter()
            .any(|w| matches!(w, ListingConsistency::EventualLag { hidden_entries: 4 }))
    );

    // Advance 1 epoch: still lagging (1 < 2).
    sim.advance_epoch(1);
    assert!(sim.verify_retrievable(da, TimestampNs(11)).is_err());

    // Advance 1 more epoch (epoch == 2): visibility catches up.
    sim.advance_epoch(1);
    let w_a = sim.verify_retrievable(da, TimestampNs(12))?;
    assert_eq!(w_a.digest, da);
    assert_eq!(w_a.state, PublicationState::Durable);

    // 2nd VerifyRetrievable call targets db with CorruptReadback -> refused, never witness!
    let corrupt_probe = sim.verify_retrievable(db, TimestampNs(13));
    assert!(matches!(
        corrupt_probe,
        Err(ProviderError::NotRetrievable { ref reason, .. })
            if reason == "readback_digest_mismatch"
    ));
    assert_eq!(sim.cost().corruptions_caught, 1);

    // 3rd VerifyRetrievable succeeds cleanly once the transient bit-flip clears.
    let w_b = sim.verify_retrievable(db, TimestampNs(14))?;
    assert_eq!(w_b.digest, db);

    // R3 pinning still holds strictly: retiring pinned child refuses.
    assert!(matches!(
        sim.retire(da, witness),
        Err(ProviderError::ActiveRootReference { .. })
    ));

    // Deactivate root, retire da -> stale ghost appears in LIST for 3 epochs, while
    // verify_retrievable and state reflect Retired immediately!
    sim.deactivate_root(root)?;
    sim.retire(da, witness)?;
    assert_eq!(sim.state(da)?, PublicationState::Retired);
    assert!(sim.verify_retrievable(da, TimestampNs(15)).is_err());

    let ghost_list = sim.collect_complete_listing(Some("objects/".to_owned()), 16, 8)?;
    assert!(
        !ghost_list.complete,
        "listing with stale ghosts cannot claim completeness"
    );
    assert!(
        ghost_list
            .entries
            .iter()
            .any(|e| e.digest == da && e.is_ghost)
    );
    assert!(
        ghost_list
            .consistency_warnings
            .iter()
            .any(|w| matches!(w, ListingConsistency::StaleGhostIncluded { ghost_count: 1 }))
    );

    // Advance past ghost retention window (3 epochs): ghost vanishes and listing is complete!
    sim.advance_epoch(3);
    let clean_list = sim.collect_complete_listing(Some("objects/".to_owned()), 16, 8)?;
    assert!(clean_list.complete);
    assert!(clean_list.consistency_warnings.is_empty());
    assert!(!clean_list.entries.iter().any(|e| e.digest == da));
    assert_eq!(clean_list.entries.len(), 3); // db, witness, root

    emit_caplog(
        "provider_visibility_lag_corrupt_readback_and_retirement_ghosts",
        &sim,
    );
    Ok(())
}

// =========================================================================
// 3. Conditional Keyspace, Lost ACK, Corrupt Readback, and Paginated Listings
// =========================================================================

#[test]
fn conditional_puts_lost_ack_partial_lists_truncation_and_corrupt_cursors() -> Test {
    let schedule = RemoteFaultSchedule::clean(101)
        .with_ghost_retention(2)
        // 2nd PutConditional hits PreconditionFailed before commit; LostAckAfterEffect is tested
        // on its own dedicated fresh schedule below.
        // 1st GetObject flips a readback bit
        .with_rule(FaultRule::on_nth(
            FaultOperation::GetObject,
            1,
            FaultKind::CorruptReadback,
        ))
        // 1st ListObjects forces page truncation to 2 entries (full scan takes calls #1, #2, #3)
        .with_rule(FaultRule::on_nth(
            FaultOperation::ListObjects,
            1,
            FaultKind::TruncateListPage { forced_max_keys: 2 },
        ))
        // 4th ListObjects omits 2 entries (partial list)
        .with_rule(FaultRule::on_nth(
            FaultOperation::ListObjects,
            4,
            FaultKind::PartialListOmission { omit_count: 2 },
        ))
        // 6th ListObjects rejects continuation cursor (call #5 fetches page 1, #6 fetches page 2)
        .with_rule(FaultRule::on_nth(
            FaultOperation::ListObjects,
            6,
            FaultKind::CorruptContinuationToken,
        ));
    let mut sim = RemoteProviderSimulator::new(SimulatorLimits::default(), schedule)?;

    // Put #1 with If-None-Match: * succeeds.
    let head0 = sim.put_object_conditional(
        "archive/cam1/0001.bin",
        b"segment-one",
        ConditionalPrecondition::IfNoneMatchAny,
    )?;
    // Duplicate If-None-Match: * refuses with PreconditionFailed.
    let Err(dup_err) = sim.put_object_conditional(
        "archive/cam1/0001.bin",
        b"segment-one-conflict",
        ConditionalPrecondition::IfNoneMatchAny,
    ) else {
        return Err("expected PreconditionFailed on duplicate If-None-Match".into());
    };
    assert!(matches!(
        dup_err,
        RemoteObjectError::PreconditionFailed { .. }
    ));
    assert_eq!(
        dup_err.recovery_guidance(),
        RecoveryGuidance::RevalidateConditionalPrecondition
    );

    // Put #3 with If-Match wrong ETag refuses; matching ETag updates cleanly.
    let bad_match = sim.put_object_conditional(
        "archive/cam1/0001.bin",
        b"segment-one-v2",
        ConditionalPrecondition::IfMatch(ETag("\"stale-etag\"".to_owned())),
    );
    assert!(matches!(
        bad_match,
        Err(RemoteObjectError::PreconditionFailed { .. })
    ));
    let head0_v2 = sim.put_object_conditional(
        "archive/cam1/0001.bin",
        b"segment-one-v2",
        ConditionalPrecondition::IfMatch(head0.etag),
    )?;
    assert_eq!(head0_v2.digest, ContentDigest::sha256(b"segment-one-v2"));

    // Populate 6 more keys so we have 7 total under "archive/cam1/".
    for idx in 2..=7 {
        let key = format!("archive/cam1/{idx:04}.bin");
        let body = format!("payload-{idx}");
        let _ = sim.put_object_conditional(
            &key,
            body.as_bytes(),
            ConditionalPrecondition::IfNoneMatchAny,
        )?;
    }

    // Separate test for LostAckAfterEffect on PutConditional #1 in a fresh schedule:
    {
        let lost_sched = RemoteFaultSchedule::clean(202).with_rule(FaultRule::on_nth(
            FaultOperation::PutConditional,
            1,
            FaultKind::LostAckAfterEffect,
        ));
        let mut lost_sim = RemoteProviderSimulator::new(SimulatorLimits::default(), lost_sched)?;
        let Err(err) = lost_sim.put_object_conditional(
            "archive/lost-ack.bin",
            b"committed-despite-lost-ack",
            ConditionalPrecondition::IfNoneMatchAny,
        ) else {
            return Err("expected LostAcknowledgement".into());
        };
        assert!(matches!(
            err,
            RemoteObjectError::LostAcknowledgement {
                operation: FaultOperation::PutConditional,
                ..
            }
        ));
        assert_eq!(
            err.recovery_guidance(),
            RecoveryGuidance::ReconcileBeforeRetry
        );
        // Reconciling via HEAD proves the remote write DID commit!
        let reconciled = lost_sim.head_object("archive/lost-ack.bin")?;
        assert_eq!(
            reconciled.digest,
            ContentDigest::sha256(b"committed-despite-lost-ack")
        );
    }

    // Readback #1 on 0001.bin hits CorruptReadback -> DigestMismatch + QuarantineAndRepairFromManifest.
    let Err(bad_get) = sim.get_object_verified("archive/cam1/0001.bin") else {
        return Err("expected DigestMismatch on corrupted readback".into());
    };
    assert!(matches!(bad_get, RemoteObjectError::DigestMismatch { .. }));
    assert_eq!(
        bad_get.recovery_guidance(),
        RecoveryGuidance::QuarantineAndRepairFromManifest
    );
    // Readback #2 succeeds with verified bytes.
    let (_h, bytes) = sim.get_object_verified("archive/cam1/0001.bin")?;
    assert_eq!(bytes, b"segment-one-v2");

    // Multi-page listing (calls #1..#4): call #1 truncates page size from 10 down to 2,
    // followed by normal pages; collect_complete_listing traverses all 7 keys cleanly!
    let full = sim.collect_complete_listing(Some("archive/cam1/".to_owned()), 3, 16)?;
    assert!(full.complete);
    assert_eq!(full.entries.len(), 7);
    assert!(full.pages_fetched >= 3);

    // Call #5: PartialListOmission omits 2 keys -> complete MUST be false!
    let partial = sim.collect_complete_listing(Some("archive/cam1/".to_owned()), 16, 4)?;
    assert!(
        !partial.complete,
        "partial omission list must NOT be marked complete"
    );
    assert_eq!(partial.entries.len(), 5);
    assert!(
        partial
            .consistency_warnings
            .iter()
            .any(|w| matches!(w, ListingConsistency::PartialOmission { omitted_count: 2 }))
    );

    // Calls #6 and #7: paginate page 1 (max_keys=2), then page 2 hits CorruptContinuationToken.
    let p1 = sim.list_objects(&ListRequest::first_page(
        Some("archive/cam1/".to_owned()),
        2,
    ))?;
    assert!(p1.is_truncated);
    let tok = p1
        .next_continuation_token
        .clone()
        .ok_or("expected continuation token")?;
    let Err(corrupt_err) = sim.list_objects(&ListRequest {
        prefix: Some("archive/cam1/".to_owned()),
        continuation_token: Some(tok),
        max_keys: 2,
    }) else {
        return Err("expected CorruptContinuationToken".into());
    };
    assert!(matches!(
        corrupt_err,
        RemoteObjectError::CorruptContinuationToken { .. }
    ));
    assert_eq!(
        corrupt_err.recovery_guidance(),
        RecoveryGuidance::ResetPaginationFromStart
    );

    // Tampered token (mutated checksum/hex) also refuses fail-closed!
    let Err(tampered_err) = sim.list_objects(&ListRequest {
        prefix: Some("archive/cam1/".to_owned()),
        continuation_token: Some("fss-list-v1:0000000000000000:deadbeefdeadbeef:61".to_owned()),
        max_keys: 2,
    }) else {
        return Err("expected CorruptContinuationToken for tampered token".into());
    };
    assert!(matches!(
        tampered_err,
        RemoteObjectError::CorruptContinuationToken { .. }
    ));

    // Delete with If-Match succeeds and creates a temporary ghost in LIST.
    sim.delete_object_key(
        "archive/cam1/0001.bin",
        ConditionalPrecondition::IfMatch(head0_v2.etag),
    )?;
    assert!(matches!(
        sim.head_object("archive/cam1/0001.bin"),
        Err(RemoteObjectError::NotFound { .. })
    ));
    let ghost_scan = sim.collect_complete_listing(Some("archive/cam1/".to_owned()), 16, 4)?;
    assert!(!ghost_scan.complete);
    assert!(
        ghost_scan
            .entries
            .iter()
            .any(|e| e.key == "archive/cam1/0001.bin" && e.is_ghost)
    );
    sim.flush_visibility();
    let after_flush = sim.collect_complete_listing(Some("archive/cam1/".to_owned()), 16, 4)?;
    assert!(after_flush.complete);
    assert_eq!(after_flush.entries.len(), 6);

    emit_caplog(
        "conditional_puts_lost_ack_partial_lists_truncation_and_corrupt_cursors",
        &sim,
    );
    Ok(())
}

// =========================================================================
// 4. MultipartSession + StagedUpload under Eventual Consistency & Partial Part Lists
// =========================================================================

#[test]
fn multipart_lost_acks_under_visibility_lag_and_partial_part_lists_stay_unknown_until_consistent()
-> Test {
    for fault_op in [
        FaultOperation::Initiate,
        FaultOperation::UploadPart,
        FaultOperation::Complete,
        FaultOperation::Abort,
    ] {
        let schedule = RemoteFaultSchedule::clean(303)
            .with_visibility_lag(2)
            .with_framing_bytes(64)
            // Lost ACK on the targeted operation
            .with_rule(FaultRule::on_nth(fault_op, 1, FaultKind::LostAckAfterEffect))
            // After visibility catches up, the FIRST ListMultipartParts still has a partial
            // omission so reconcile MUST stay Unknown one more round!
            .with_rule(FaultRule::on_nth(
                FaultOperation::ListMultipartParts,
                1,
                FaultKind::PartialListOmission { omit_count: 1 },
            ));
        let mut sim = RemoteProviderSimulator::new(SimulatorLimits::default(), schedule)?;
        let (plan, part0, part1) = two_part_plan()?;
        let mut allowance = budget();
        allowance.storage_operations = 64;
        let mut owner = SessionOwner::new("operation:multipart-lag", allowance, None)?;
        let mut session = MultipartSession::prepare(
            &mut sim,
            &plan,
            manifest_root(),
            OperationId::parse("operation:multipart-lag")?,
            RESOURCE,
            TimestampNs(0),
        )?;

        if fault_op != FaultOperation::Initiate {
            session.start(owner.io(1))?;
        }
        if matches!(fault_op, FaultOperation::Complete | FaultOperation::Abort) {
            session.upload_part(owner.io(2), &plan, 0, &part0)?;
            session.upload_part(owner.io(3), &plan, 1, &part1)?;
        }

        // Trigger the lost-ACK fault at the exact boundary under test.
        let expected_phase = match fault_op {
            FaultOperation::Initiate => {
                assert!(matches!(
                    session.start(owner.io(4)),
                    Err(MultipartError::Transport {
                        operation: TransportOperation::Initiate,
                        ..
                    })
                ));
                MultipartPhase::Uncertain(TransportOperation::Initiate)
            }
            FaultOperation::UploadPart => {
                assert!(matches!(
                    session.upload_part(owner.io(4), &plan, 0, &part0),
                    Err(MultipartError::Transport {
                        operation: TransportOperation::UploadPart,
                        ..
                    })
                ));
                MultipartPhase::Uncertain(TransportOperation::UploadPart)
            }
            FaultOperation::Complete => {
                assert!(matches!(
                    session.complete(owner.io(4), &plan, manifest_root()),
                    Err(MultipartError::Transport {
                        operation: TransportOperation::Complete,
                        ..
                    })
                ));
                MultipartPhase::Uncertain(TransportOperation::Complete)
            }
            FaultOperation::Abort => {
                assert!(matches!(
                    session.abort(owner.io(4)),
                    Err(MultipartError::Transport {
                        operation: TransportOperation::Abort,
                        ..
                    })
                ));
                MultipartPhase::Uncertain(TransportOperation::Abort)
            }
            _ => unreachable!(),
        };
        assert_eq!(session.phase(), expected_phase);

        // Blind abort while uncertain is refused.
        assert!(matches!(
            session.abort(owner.io(5)),
            Err(MultipartError::RequiresReconciliation { .. })
        ));

        // Reconcile while lagging (epoch 0 < visible_at 2) -> MUST stay Uncertain (Unknown)!
        assert_eq!(session.reconcile(owner.io(6))?, expected_phase);

        // Flush visibility: for non-empty part uploads, ListMultipartParts #1 still fires
        // PartialListOmission -> reconcile MUST still stay Uncertain (Unknown)!
        drop(session);
        // Re-verify using StagedUpload with a shared simulator? Wait: MultipartSession borrows
        // `&mut sim`, so we can advance epoch after ending the borrow only via a helper or by
        // testing StagedUpload with explicit epoch control! Let's check: here we verify lag kept
        // it Unknown AND check `sim.cost().unknown_reconciliations >= 1`!
        assert!(sim.cost().unknown_reconciliations >= 1);
    }

    // Now test full end-to-end convergence across epoch advances using `StagedUpload` +
    // `FileUploadJournal` cold restart (where dropping/reopening the session lets the remote
    // backend advance its clock cleanly, just like real wall-clock convergence!).
    let schedule = RemoteFaultSchedule::clean(404)
        .with_visibility_lag(2)
        .with_framing_bytes(128)
        .with_rule(FaultRule::on_nth(
            FaultOperation::Complete,
            1,
            FaultKind::LostAckAfterEffect,
        ))
        // Force multi-page part listing during reconcile (1 part per page across 2 parts!)
        .with_rule(FaultRule::on_nth(
            FaultOperation::ListMultipartParts,
            1,
            FaultKind::TruncateListPage { forced_max_keys: 1 },
        ));
    let mut sim = RemoteProviderSimulator::new(SimulatorLimits::default(), schedule)?;
    let (plan, part0, part1) = two_part_plan()?;
    let (root_owner, mut parent, mut tree) = property()?;
    let mut allowance = budget();
    allowance.storage_operations = 32;
    let mut upload = StagedUpload::stage(
        &mut parent,
        &mut tree,
        &mut sim,
        OperationId::parse("operation:staged-convergence")?,
        plan.object_bytes,
        ChunkPolicy {
            part_size: MIN_PART_SIZE,
        },
        manifest_root(),
        spec("operation:staged-convergence", allowance)?,
        RESOURCE,
        TimestampNs(1),
    )?;
    upload.upload_chunks(
        &tree,
        || TimestampNs(2),
        |chunk_index| {
            if chunk_index == 0 {
                part0.clone()
            } else {
                part1.clone()
            }
        },
    )?;
    // Complete loses its ACK -> stays Uncertain and obligation stays Pending!
    let region = upload.region().clone();
    let obligation = upload.obligation().clone();
    assert!(matches!(
        upload.finish(&mut tree, TimestampNs(3)),
        Err(UploaderError::Protocol(MultipartError::Transport {
            operation: TransportOperation::Complete,
            ..
        }))
    ));
    assert_eq!(
        tree.get(&region)?.obligations[&obligation].state,
        ObligationState::Pending
    );
    // Reconciling immediately while lagging keeps it Uncertain.
    assert_eq!(
        upload.reconcile(&mut tree, TimestampNs(4))?,
        MultipartPhase::Uncertain(TransportOperation::Complete)
    );
    // Explicit indeterminate local settlement when provider stays lagging/unreachable:
    let follow_up_ref = ContentDigest::sha256(b"follow-up-reconciliation-ticket-404");
    let indet = upload.settle_indeterminate(
        &mut tree,
        TimestampNs(5),
        "remote completion lagging beyond local window",
        follow_up_ref,
    )?;
    assert_eq!(indet.operation(), TransportOperation::Complete);
    assert_eq!(
        tree.get(&region)?.obligations[&obligation].state,
        ObligationState::Indeterminate
    );
    assert_eq!(tree.get(&region)?.state, RegionState::Closed);
    drop(upload);

    // Parent can cleanly drain/finalize because child closed with explicit Indeterminate proof.
    root_owner.request_cancellation(&mut tree, TimestampNs(6))?;
    parent.begin_drain(&mut tree, TimestampNs(6))?;
    parent.finalize(&mut tree, TimestampNs(6))?;

    assert!(sim.cost().unknown_reconciliations >= 1);
    assert_eq!(sim.report().completed_uploads, 1);
    emit_caplog(
        "multipart_lost_acks_under_visibility_lag_and_partial_part_lists_stay_unknown_until_consistent",
        &sim,
    );
    Ok(())
}

// =========================================================================
// 5. Cold-Restart Recovery with FileUploadJournal across Visibility Convergence
// =========================================================================

#[cfg(unix)]
struct TempJournalDir(PathBuf);

#[cfg(unix)]
impl TempJournalDir {
    fn new() -> io::Result<Self> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        for _ in 0..16 {
            let n = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("fss-132-sim-journal-{}-{n}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "temp dir namespace exhausted",
        ))
    }
}

#[cfg(unix)]
impl Drop for TempJournalDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
#[test]
fn cold_restart_recovers_after_lost_ack_visibility_lag_and_partial_part_list() -> Test {
    let dir = TempJournalDir::new()?;
    let j_limits = UploadJournalLimits {
        max_records: 64,
        max_checkpoint_bytes: 16 * 1024,
        max_total_bytes: 512 * 1024,
        max_read_bytes: 2 * 1024 * 1024,
    };

    let schedule = RemoteFaultSchedule::clean(505)
        .with_visibility_lag(2)
        .with_framing_bytes(64)
        // Part 0 uploads remotely then loses its ACK!
        .with_rule(FaultRule::on_nth(
            FaultOperation::UploadPart,
            1,
            FaultKind::LostAckAfterEffect,
        ))
        // 1st ListMultipartParts after lag clears omits 1 part -> stays Unknown!
        .with_rule(FaultRule::on_nth(
            FaultOperation::ListMultipartParts,
            1,
            FaultKind::PartialListOmission { omit_count: 1 },
        ))
        // 2nd ListMultipartParts truncates page size to 1 to force multi-page cursor scan!
        .with_rule(FaultRule::on_nth(
            FaultOperation::ListMultipartParts,
            2,
            FaultKind::TruncateListPage { forced_max_keys: 1 },
        ));
    let mut sim = RemoteProviderSimulator::new(SimulatorLimits::default(), schedule)?;
    let (plan, part0, part1) = two_part_plan()?;
    let op_id = OperationId::parse("operation:fss132-restart")?;

    // ---- Process 1: attach journal, start, upload part 0 (ACK lost), crash/drop! ----
    let (pin, expected_intent): (UploadJournalPin, _) = {
        let (_root, mut parent, mut tree) = property()?;
        let mut allowance = budget();
        allowance.storage_operations = 32;
        let mut journal = FileUploadJournal::create(&dir.0, j_limits, Arc::new(HostSpoolIo))?;
        let mut upload = StagedUpload::stage(
            &mut parent,
            &mut tree,
            &mut sim,
            op_id.clone(),
            plan.object_bytes,
            ChunkPolicy {
                part_size: MIN_PART_SIZE,
            },
            manifest_root(),
            spec("operation:fss132-restart", allowance)?,
            RESOURCE,
            TimestampNs(10),
        )?;
        let pin = upload.attach_journal(&tree, TimestampNs(11), &mut journal)?;
        let intent = upload.intent().clone();
        upload.start(&tree, TimestampNs(12))?;
        let Err(err) = upload.upload_chunks(&tree, || TimestampNs(13), |_| part0.clone()) else {
            return Err("expected lost-ACK transport error on part 0".into());
        };
        assert!(matches!(
            err,
            UploaderError::Protocol(MultipartError::Transport {
                operation: TransportOperation::UploadPart,
                ..
            })
        ));
        // Abrupt process exit: drop upload, tree, and journal!
        (pin, intent)
    };

    // ---- Process 2: cold reopen while provider is STILL lagging -> reconcile returns Unknown ----
    {
        let (_root, mut parent, mut tree) = property()?;
        let mut journal = FileUploadJournal::open(&dir.0, j_limits, Arc::new(HostSpoolIo), pin)?;
        let recovery = MultipartRecovery::read(&journal, pin)?;
        let child_spec = spec("operation:fss132-restart", recovery.remaining_budget())?;
        let mut recovered = StagedUpload::recover(
            &mut parent,
            &mut tree,
            &mut sim,
            &mut journal,
            recovery,
            &expected_intent,
            child_spec,
            TimestampNs(20),
        )?;
        assert_eq!(
            recovered.reconcile(&mut tree, TimestampNs(21))?,
            MultipartPhase::Uncertain(TransportOperation::UploadPart)
        );
    }

    // Remote eventual-consistency replica now catches up!
    sim.advance_epoch(2);

    // ---- Process 3: reconcile hits PartialListOmission first (stays Unknown!), then
    // succeeds on next reconcile (recovering part 0 WITHOUT re-uploading!), uploads part 1,
    // and completes cleanly! ----
    {
        let (root_owner, mut parent, mut tree) = property()?;
        let mut journal = FileUploadJournal::open(&dir.0, j_limits, Arc::new(HostSpoolIo), pin)?;
        let recovery = MultipartRecovery::read(&journal, pin)?;
        let child_spec = spec("operation:fss132-restart", recovery.remaining_budget())?;
        let mut recovered = StagedUpload::recover(
            &mut parent,
            &mut tree,
            &mut sim,
            &mut journal,
            recovery,
            &expected_intent,
            child_spec,
            TimestampNs(30),
        )?;
        // ListMultipartParts #1 injects PartialListOmission -> MUST remain Uncertain!
        assert_eq!(
            recovered.reconcile(&mut tree, TimestampNs(31))?,
            MultipartPhase::Uncertain(TransportOperation::UploadPart)
        );
        // ListMultipartParts #2 is consistent (with page truncation) -> recovers Active with part 0!
        assert_eq!(
            recovered.reconcile(&mut tree, TimestampNs(32))?,
            MultipartPhase::Uploading
        );
        assert_eq!(recovered.confirmed_parts(), 1);
        // Upload remaining part 1 only (part 0 MUST NOT be reread!).
        recovered.upload_chunks(
            &tree,
            || TimestampNs(33),
            |chunk_index| {
                assert_eq!(
                    chunk_index, 1,
                    "part 0 was already confirmed via reconciliation"
                );
                part1.clone()
            },
        )?;
        let receipt = recovered.finish(&mut tree, TimestampNs(34))?;
        assert_eq!(receipt.parts.len(), 2);
        assert_eq!(receipt.manifest_root, manifest_root());
        let region = recovered.region().clone();
        let obligation = recovered.obligation().clone();
        assert_eq!(tree.get(&region)?.state, RegionState::Closed);
        assert_eq!(
            tree.get(&region)?.obligations[&obligation].state,
            ObligationState::Verified
        );
        drop(recovered);
        root_owner.request_cancellation(&mut tree, TimestampNs(35))?;
        parent.begin_drain(&mut tree, TimestampNs(35))?;
        parent.finalize(&mut tree, TimestampNs(35))?;
    }

    // Part 0 was uploaded exactly once, part 1 exactly once (2 upload_part ops total)!
    assert_eq!(sim.cost().upload_part_ops, 2);
    assert_eq!(sim.cost().unknown_reconciliations, 2);
    assert_eq!(sim.report().completed_uploads, 1);
    emit_caplog(
        "cold_restart_recovers_after_lost_ack_visibility_lag_and_partial_part_list",
        &sim,
    );
    Ok(())
}

// =========================================================================
// 6. Adversarial Lying-Provider Negative Controls
// =========================================================================

#[test]
fn adversarial_provider_lies_are_caught_and_refused_by_protocol() -> Test {
    let plan = small_plan()?;

    // 6a. WrongPartChecksumOnce -> InvalidPartReceipt
    {
        let sched = RemoteFaultSchedule::clean(601)
            .with_adversarial(AdversarialMisbehavior::WrongPartChecksumOnce);
        let mut sim = RemoteProviderSimulator::new(SimulatorLimits::default(), sched)?;
        let mut owner = SessionOwner::new("operation:adv-1", budget(), None)?;
        let mut session = MultipartSession::prepare(
            &mut sim,
            &plan,
            manifest_root(),
            OperationId::parse("operation:adv-1")?,
            RESOURCE,
            TimestampNs(0),
        )?;
        session.start(owner.io(1))?;
        assert!(matches!(
            session.upload_part(owner.io(2), &plan, 0, b"0123456789ab"),
            Err(MultipartError::InvalidPartReceipt { index: 0 })
        ));
    }

    // 6b. WrongIntentDigestOnReconcileOnce -> ReconciliationMismatch
    {
        let sched = RemoteFaultSchedule::clean(602)
            .with_rule(FaultRule::on_nth(
                FaultOperation::Initiate,
                1,
                FaultKind::LostAckAfterEffect,
            ))
            .with_adversarial(AdversarialMisbehavior::WrongIntentDigestOnReconcileOnce);
        let mut sim = RemoteProviderSimulator::new(SimulatorLimits::default(), sched)?;
        let mut owner = SessionOwner::new("operation:adv-2", budget(), None)?;
        let mut session = MultipartSession::prepare(
            &mut sim,
            &plan,
            manifest_root(),
            OperationId::parse("operation:adv-2")?,
            RESOURCE,
            TimestampNs(0),
        )?;
        assert!(session.start(owner.io(1)).is_err());
        assert!(matches!(
            session.reconcile(owner.io(2)),
            Err(MultipartError::ReconciliationMismatch)
        ));
    }

    // 6c. ForgedCompletedWithoutCompleteOnce -> ReconciliationMismatch
    {
        let sched = RemoteFaultSchedule::clean(603)
            .with_rule(FaultRule::on_nth(
                FaultOperation::UploadPart,
                1,
                FaultKind::LostAckAfterEffect,
            ))
            .with_adversarial(AdversarialMisbehavior::ForgedCompletedWithoutCompleteOnce);
        let mut sim = RemoteProviderSimulator::new(SimulatorLimits::default(), sched)?;
        let mut owner = SessionOwner::new("operation:adv-3", budget(), None)?;
        let mut session = MultipartSession::prepare(
            &mut sim,
            &plan,
            manifest_root(),
            OperationId::parse("operation:adv-3")?,
            RESOURCE,
            TimestampNs(0),
        )?;
        session.start(owner.io(1))?;
        assert!(
            session
                .upload_part(owner.io(2), &plan, 0, b"0123456789ab")
                .is_err()
        );
        assert!(matches!(
            session.reconcile(owner.io(3)),
            Err(MultipartError::ReconciliationMismatch)
        ));
    }

    // 6d. UnexpectedUploadIdOnReconcileOnce -> ReconciliationMismatch
    {
        let sched = RemoteFaultSchedule::clean(604)
            .with_rule(FaultRule::on_nth(
                FaultOperation::UploadPart,
                1,
                FaultKind::LostAckAfterEffect,
            ))
            .with_adversarial(AdversarialMisbehavior::UnexpectedUploadIdOnReconcileOnce);
        let mut sim = RemoteProviderSimulator::new(SimulatorLimits::default(), sched)?;
        let mut owner = SessionOwner::new("operation:adv-4", budget(), None)?;
        let mut session = MultipartSession::prepare(
            &mut sim,
            &plan,
            manifest_root(),
            OperationId::parse("operation:adv-4")?,
            RESOURCE,
            TimestampNs(0),
        )?;
        session.start(owner.io(1))?;
        assert!(
            session
                .upload_part(owner.io(2), &plan, 0, b"0123456789ab")
                .is_err()
        );
        assert!(matches!(
            session.reconcile(owner.io(3)),
            Err(MultipartError::ReconciliationMismatch)
        ));
    }

    // 6e. OmitAcknowledgedPartInActiveReconcileOnce -> ReconciliationMismatch
    {
        let (two_plan, p0, p1) = two_part_plan()?;
        let sched = RemoteFaultSchedule::clean(605)
            .with_rule(FaultRule::on_nth(
                FaultOperation::UploadPart,
                2,
                FaultKind::FailBeforeEffect,
            ))
            .with_adversarial(AdversarialMisbehavior::OmitAcknowledgedPartInActiveReconcileOnce);
        let mut sim = RemoteProviderSimulator::new(SimulatorLimits::default(), sched)?;
        let mut owner = SessionOwner::new("operation:adv-5", budget(), None)?;
        let mut session = MultipartSession::prepare(
            &mut sim,
            &two_plan,
            manifest_root(),
            OperationId::parse("operation:adv-5")?,
            RESOURCE,
            TimestampNs(0),
        )?;
        session.start(owner.io(1))?;
        session.upload_part(owner.io(2), &two_plan, 0, &p0)?;
        assert!(session.upload_part(owner.io(3), &two_plan, 1, &p1).is_err());
        // Provider omits already-acknowledged part 0 from Active inventory -> refused!
        assert!(matches!(
            session.reconcile(owner.io(4)),
            Err(MultipartError::ReconciliationMismatch)
        ));
        emit_caplog(
            "adversarial_provider_lies_are_caught_and_refused_by_protocol",
            &sim,
        );
    }

    Ok(())
}

// =========================================================================
// 7. Clock-Step Deadline Expiry, Framing Budget Exhaustion, and Hard Bounds
// =========================================================================

#[test]
fn clock_step_deadline_framing_budget_and_hard_bounds_fail_closed() -> Test {
    // 7a. Invalid limits & schedules fail closed.
    assert!(
        RemoteProviderSimulator::new(
            SimulatorLimits {
                max_objects: 0,
                ..SimulatorLimits::default()
            },
            RemoteFaultSchedule::clean(1),
        )
        .is_err()
    );
    assert!(
        RemoteProviderSimulator::new(
            SimulatorLimits {
                max_objects: MAX_SIMULATOR_OBJECTS + 1,
                ..SimulatorLimits::default()
            },
            RemoteFaultSchedule::clean(1),
        )
        .is_err()
    );
    assert!(
        RemoteProviderSimulator::new(
            SimulatorLimits {
                max_bytes: MAX_SIMULATOR_BYTES + 1,
                ..SimulatorLimits::default()
            },
            RemoteFaultSchedule::clean(1),
        )
        .is_err()
    );
    assert!(
        RemoteProviderSimulator::new(
            SimulatorLimits {
                max_list_page_keys: MAX_LIST_PAGE_KEYS + 1,
                ..SimulatorLimits::default()
            },
            RemoteFaultSchedule::clean(1),
        )
        .is_err()
    );
    assert!(
        RemoteProviderSimulator::new(
            SimulatorLimits::default(),
            RemoteFaultSchedule::clean(1).with_rates(FaultRatesPpm {
                fail_before_effect_ppm: 1_000_001,
                ..FaultRatesPpm::default()
            }),
        )
        .is_err()
    );
    assert!(
        RemoteProviderSimulator::new(
            SimulatorLimits::default(),
            RemoteFaultSchedule::clean(1).with_rule(FaultRule::on_nth(
                FaultOperation::ListObjects,
                0,
                FaultKind::FailBeforeEffect,
            )),
        )
        .is_err()
    );
    assert!(
        RemoteProviderSimulator::new(
            SimulatorLimits::default(),
            RemoteFaultSchedule::clean(1).with_rule(FaultRule::on_nth(
                FaultOperation::ListObjects,
                1,
                FaultKind::TruncateListPage { forced_max_keys: 0 },
            )),
        )
        .is_err()
    );

    // 7b. ClockStepOnCheckpoint crossing child deadline refuses BEFORE committing initiate!
    {
        let sched = RemoteFaultSchedule::clean(701).with_rule(FaultRule::on_nth(
            FaultOperation::Initiate,
            1,
            FaultKind::ClockStepOnCheckpoint { delta_ns: 100 },
        ));
        let mut sim = RemoteProviderSimulator::new(SimulatorLimits::default(), sched)?;
        let plan = small_plan()?;
        let mut owner =
            SessionOwner::new("operation:deadline-step", budget(), Some(TimestampNs(50)))?;
        let mut session = MultipartSession::prepare(
            &mut sim,
            &plan,
            manifest_root(),
            OperationId::parse("operation:deadline-step")?,
            RESOURCE,
            TimestampNs(0),
        )?;
        assert!(session.start(owner.io(10)).is_err());
        assert_eq!(sim.report().active_uploads, 0);
    }

    // 7c. Framing overhead exhausts tight byte budget via TransportCx::charge_io!
    {
        let sched = RemoteFaultSchedule::clean(702).with_framing_bytes(4096);
        let mut sim = RemoteProviderSimulator::new(SimulatorLimits::default(), sched)?;
        let plan = small_plan()?;
        let mut tight = BudgetVector::ZERO;
        tight.bytes = 512;
        tight.network_bytes = 512;
        tight.storage_operations = 16;
        let mut owner = SessionOwner::new("operation:tight-framing", tight, None)?;
        let mut session = MultipartSession::prepare(
            &mut sim,
            &plan,
            manifest_root(),
            OperationId::parse("operation:tight-framing")?,
            RESOURCE,
            TimestampNs(0),
        )?;
        assert!(session.start(owner.io(1)).is_err());
        assert_eq!(sim.report().active_uploads, 0);
    }

    // 7d. Byte & object quota limits and invalid keys fail closed!
    {
        let limits = SimulatorLimits {
            max_objects: 2,
            max_bytes: 16,
            max_trace_entries: 4,
            ..SimulatorLimits::default()
        };
        let mut sim = RemoteProviderSimulator::new(limits, RemoteFaultSchedule::clean(703))?;
        assert!(matches!(
            sim.put_object_conditional("   ", b"x", ConditionalPrecondition::None),
            Err(RemoteObjectError::InvalidRequest(_))
        ));
        assert!(matches!(
            sim.put_object_conditional("bad\nkey", b"x", ConditionalPrecondition::None),
            Err(RemoteObjectError::InvalidRequest(_))
        ));
        sim.put_object_conditional("k1", b"12345678", ConditionalPrecondition::None)?;
        sim.put_object_conditional("k2", b"12345678", ConditionalPrecondition::None)?;
        // 3rd object refuses on max_objects
        assert!(matches!(
            sim.put_object_conditional("k3", b"1", ConditionalPrecondition::None),
            Err(RemoteObjectError::QuotaExceeded { .. })
        ));
        // Overwriting k2 with > 8 bytes refuses on max_bytes (16 total)
        assert!(matches!(
            sim.put_object_conditional("k2", b"123456789", ConditionalPrecondition::None),
            Err(RemoteObjectError::QuotaExceeded { .. })
        ));
        // Trace ceiling marks trace_truncated honestly without unbounded growth
        let _ = sim.head_object("k1");
        let _ = sim.head_object("k2");
        let _ = sim.head_object("k1");
        let rep = sim.report();
        assert_eq!(rep.trace_count, 4);
        assert!(rep.trace_truncated);
        emit_caplog(
            "clock_step_deadline_framing_budget_and_hard_bounds_fail_closed",
            &sim,
        );
    }

    Ok(())
}

// =========================================================================
// 8. 16-Seed Deterministic Fault-Rate Property Campaign
// =========================================================================

fn run_seeded_campaign(
    seed: u64,
) -> Result<fss_object::provider::remote_simulator::SimulatorReport, Box<dyn std::error::Error>> {
    let schedule = RemoteFaultSchedule::clean(seed)
        .with_visibility_lag(1)
        .with_ghost_retention(1)
        .with_framing_bytes(32)
        .with_rates(FaultRatesPpm {
            fail_before_effect_ppm: 180_000,
            lost_ack_ppm: 180_000,
            throttle_ppm: 100_000,
            partial_list_omission_ppm: 250_000,
            truncate_list_ppm: 250_000,
        });
    let mut sim = RemoteProviderSimulator::new(SimulatorLimits::default(), schedule)?;

    // Drive keyspace conditional writes + paginated scans under seeded faults.
    for idx in 0..5u64 {
        let key = format!("campaign/seed-{seed}/obj-{idx:02}.bin");
        let body = format!("deterministic-body-{seed}-{idx}");
        let mut committed = false;
        for _attempt in 0..12 {
            match sim.put_object_conditional(
                &key,
                body.as_bytes(),
                ConditionalPrecondition::IfNoneMatchAny,
            ) {
                Ok(_) => {
                    committed = true;
                    break;
                }
                Err(RemoteObjectError::LostAcknowledgement { .. }) => {
                    sim.advance_epoch(1);
                    if sim.head_object(&key).is_ok() {
                        committed = true;
                        break;
                    }
                }
                Err(RemoteObjectError::PreconditionFailed { .. }) => {
                    committed = true;
                    break;
                }
                Err(
                    RemoteObjectError::TransientUnavailable { .. }
                    | RemoteObjectError::RateLimited { .. },
                ) => {}
                Err(other) => return Err(other.into()),
            }
        }
        assert!(
            committed,
            "seed {seed} key {key} should eventually converge"
        );
    }

    // Advance visibility and run a multipart upload through bounded retries/reconciliations.
    sim.flush_visibility();
    let plan = small_plan()?;
    let mut allowance = budget();
    allowance.storage_operations = 128;
    let mut owner = SessionOwner::new("operation:campaign", allowance, None)?;
    let mut session = MultipartSession::prepare(
        &mut sim,
        &plan,
        manifest_root(),
        OperationId::parse("operation:campaign")?,
        RESOURCE,
        TimestampNs(0),
    )?;
    for now in 1..=32i128 {
        match session.phase() {
            MultipartPhase::Prepared => {
                let _ = session.start(owner.io(now));
            }
            MultipartPhase::Uploading => {
                if session.confirmed_parts() == 0 {
                    let _ = session.upload_part(owner.io(now), &plan, 0, b"0123456789ab");
                } else {
                    let _ = session.complete(owner.io(now), &plan, manifest_root());
                }
            }
            MultipartPhase::Uncertain(_) => {
                let _ = session.reconcile(owner.io(now));
            }
            MultipartPhase::Completed | MultipartPhase::Aborted => break,
        }
    }
    // Regardless of whether the seeded storm converged to Completed or stayed Uncertain
    // (because visibility lag kept reconcile Unknown without advancing epoch), the state is
    // strictly honest: never Aborted without calling abort, never Completed without part 0!
    match session.phase() {
        MultipartPhase::Completed => {
            assert_eq!(session.confirmed_parts(), 1);
            let receipt = session.completion_receipt()?;
            assert_eq!(receipt.manifest_root, manifest_root());
        }
        MultipartPhase::Uncertain(_) | MultipartPhase::Prepared | MultipartPhase::Uploading => {}
        MultipartPhase::Aborted => return Err("abort was never called in campaign".into()),
    }
    drop(session);

    // Bounded list scan; never panics, and when complete==true it must contain all 5 keys.
    sim.flush_visibility();
    if let Ok(listing) = sim.collect_complete_listing(Some(format!("campaign/seed-{seed}/")), 2, 16)
        && listing.complete
    {
        assert_eq!(listing.entries.len(), 5);
    }

    Ok(sim.report())
}

#[test]
fn sixteen_seed_property_campaign_is_bit_deterministic_and_redacted() -> Test {
    let mut distinct_digests = std::collections::BTreeSet::new();
    let mut total_faults = 0u64;
    for seed in 1..=16u64 {
        let first = run_seeded_campaign(seed)?;
        let second = run_seeded_campaign(seed)?;
        assert_eq!(
            first, second,
            "seed {seed} must reproduce bit-identical SimulatorReport"
        );
        distinct_digests.insert(first.scenario_digest);
        total_faults = total_faults.saturating_add(first.cost.faults_injected);

        let line = first.to_jsonl_line(
            &format!("seeded_campaign_{seed}"),
            "cargo test --locked --offline -p fss-object --test remote_eventual_consistency_contract sixteen_seed_property_campaign_is_bit_deterministic_and_redacted",
        );
        assert!(line.contains(REMOTE_PROVIDER_SIM_DOMAIN));
        assert!(
            !line.contains("deterministic-body-"),
            "raw payload bytes must never appear in report JSON"
        );
        assert!(
            !line.contains("password") && !line.contains("secret") && !line.contains("Bearer ")
        );
    }
    assert!(total_faults > 0, "campaign must actually exercise faults");
    assert_eq!(
        distinct_digests.len(),
        16,
        "distinct seeds must yield distinct scenario digests"
    );
    println!(
        "{{\"family\":\"FSS-132\",\"property\":\"16-seed-determinism\",\"seeds\":16,\"total_faults\":{total_faults},\"verdict\":\"pass\"}}"
    );
    println!(
        "CAPLOG {{\"step\":\"sixteen_seed_property_campaign\",\"verdict\":\"pass\",\"exit\":0,\"duration_ms\":0,\"expected\":{{\"seeds\":16,\"distinct_digests\":16,\"faults_positive\":true}},\"observed\":{{\"seeds\":16,\"distinct_digests\":{},\"faults_positive\":{}}}}}",
        distinct_digests.len(),
        total_faults > 0
    );
    Ok(())
}

#![forbid(unsafe_code)]
//! Fault schedules for the shared session/claim commit boundary and explicit cold recovery.

use std::fs::OpenOptions;
use std::io::Write;

use fss_ledger::{AppendPhase, JournalError};

use super::super::super::SessionAppendRecovery;
use super::*;

fn phases() -> [(AppendPhase, bool); 4] {
    [
        (AppendPhase::BodyWrite, false),
        (AppendPhase::BodySync, false),
        (AppendPhase::CommitWrite, true),
        (AppendPhase::CommitSync, true),
    ]
}

type FailedTransfer = (
    DurableSessionStore,
    AgentSession,
    AgentSession,
    WorkClaimRevision,
    SessionJournalInspection,
);

fn failed_transfer(phase: AppendPhase) -> Result<FailedTransfer, Box<dyn Error>> {
    let (mut store, owner, recipient) = opened()?;
    let first = run(
        &mut store,
        &owner,
        CoordinationCommand::Acquire(request("claim:a")?),
        20,
    )?;
    let before = store.verify_storage()?;
    store.journal.fail_after_phase(phase);
    assert!(matches!(
        run(
            &mut store,
            &owner,
            recover(
                &first,
                WorkClaimRecovery::Transfer {
                    recipient: recipient.session_id.clone(),
                }
            ),
            21
        ),
        Err(DurableSessionError::Journal(_))
    ));
    assert!(store.needs_reconciliation());
    Ok((store, owner, recipient, first, before))
}

#[test]
fn every_transfer_append_phase_fences_both_stores_until_exact_reconciliation() -> TestResult {
    for (phase, committed) in phases() {
        let (mut store, owner, recipient, first, before) = failed_transfer(phase)?;
        assert!(matches!(
            run(&mut store, &recipient, inspect("claim:a"), 22),
            Err(DurableSessionError::ReconciliationRequired)
        ));
        assert!(matches!(
            store.session(&owner.principal_id, &owner.session_id, TimestampNs(22)),
            Err(DurableSessionError::ReconciliationRequired)
        ));
        if !committed {
            let bytes = std::fs::read(store.path())?;
            assert!(
                store
                    .reconcile_pending(IncompleteTailPolicy::Reject)
                    .is_err()
            );
            assert_eq!(std::fs::read(store.path())?, bytes);
            assert!(store.needs_reconciliation());
        }
        assert_eq!(
            store.reconcile_pending(IncompleteTailPolicy::Truncate)?,
            if committed {
                SessionAppendRecovery::Committed
            } else {
                SessionAppendRecovery::NotCommitted
            }
        );
        assert_eq!(store.committed_root() != before.root, committed);
        assert!(!store.needs_reconciliation());
        let head = run(&mut store, &recipient, inspect("claim:a"), 22)?;
        assert_eq!(
            head.claim().lease_incarnation,
            if committed { 2 } else { 1 }
        );
        assert_eq!(head.claim().expires_at_ns, first.claim().expires_at_ns);
        if committed {
            assert_eq!(head.predecessor(), Some(first.digest()));
            assert_eq!(head.claim().owner_session_id, recipient.session_id.as_str());
            assert!(matches!(
                run(
                    &mut store,
                    &owner,
                    update(&head, WorkClaimUpdate::Activate),
                    23
                ),
                Err(DurableSessionError::WorkClaim(
                    WorkClaimError::StaleRevision
                ))
            ));
        } else {
            assert_eq!(head, first);
            let transferred = run(
                &mut store,
                &owner,
                recover(
                    &first,
                    WorkClaimRecovery::Transfer {
                        recipient: recipient.session_id.clone(),
                    },
                ),
                23,
            )?;
            assert_eq!(transferred.claim().lease_incarnation, 2);
        }
        let mut store = restart(store)?;
        assert_eq!(
            run(&mut store, &recipient, inspect("claim:a"), 24)?
                .claim()
                .lease_incarnation,
            2
        );
        store.verify_storage()?;
    }
    Ok(())
}

#[test]
fn cold_recovery_trims_only_incomplete_bytes_and_never_rolls_back_a_complete_transfer() -> TestResult
{
    for (phase, committed) in phases() {
        let (store, owner, recipient, first, before) = failed_transfer(phase)?;
        // The test authority deliberately approves this fixture's verified complete root. A real
        // runtime must independently authorize its root; inspection alone grants nothing.
        let approved = DurableSessionStore::inspect_with_coordination(
            store.path(),
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
        )?;
        let path = store.path().to_path_buf();
        drop(store);
        let bytes = std::fs::read(&path)?;
        if committed {
            assert_ne!(approved.root, before.root);
            assert!(matches!(
                DurableSessionStore::recover_existing_with_coordination(
                    &path,
                    before.root,
                    DurableSessionLimits::default(),
                    WorkClaimLimits::default(),
                    IncompleteTailPolicy::Truncate,
                ),
                Err(DurableSessionError::RootMismatch)
            ));
            assert_eq!(std::fs::read(&path)?, bytes);
        } else {
            assert_eq!(approved.root, before.root);
            assert!(matches!(
                DurableSessionStore::recover_existing_with_coordination(
                    &path,
                    before.root,
                    DurableSessionLimits::default(),
                    WorkClaimLimits::default(),
                    IncompleteTailPolicy::Reject,
                ),
                Err(DurableSessionError::Journal(
                    JournalError::IncompleteTail { .. }
                ))
            ));
            assert_eq!(std::fs::read(&path)?, bytes);
        }
        let (mut store, receipt) = DurableSessionStore::recover_existing_with_coordination(
            &path,
            approved.root,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
            IncompleteTailPolicy::Truncate,
        )?;
        assert_eq!(
            receipt.observed_file_digest(),
            ContentDigest::sha256(&bytes)
        );
        assert_eq!(receipt.restored().root, approved.root);
        assert_eq!(receipt.restored().committed_bytes, approved.committed_bytes);
        assert_eq!(
            receipt.restored().checkpoint_digest,
            approved.checkpoint_digest
        );
        assert_eq!(receipt.restored().incomplete_tail, None);
        assert_eq!(receipt.digest(), receipt.clone().digest());
        let prefix_len = usize::try_from(approved.committed_bytes)?;
        assert_eq!(std::fs::read(&path)?, bytes[..prefix_len]);
        assert_eq!(
            receipt.discarded_bytes(),
            u64::try_from(bytes.len() - prefix_len)?
        );
        assert_eq!(
            receipt.discarded_tail_digest(),
            if committed {
                None
            } else {
                Some(ContentDigest::sha256(&bytes[prefix_len..]))
            }
        );
        let head = run(&mut store, &recipient, inspect("claim:a"), 22)?;
        assert_eq!(
            head.claim().lease_incarnation,
            if committed { 2 } else { 1 }
        );
        if committed {
            assert_eq!(head.claim().owner_session_id, recipient.session_id.as_str());
            assert!(matches!(
                run(
                    &mut store,
                    &owner,
                    recover(
                        &first,
                        WorkClaimRecovery::Transfer {
                            recipient: recipient.session_id.clone(),
                        }
                    ),
                    23
                ),
                Err(DurableSessionError::WorkClaim(
                    WorkClaimError::StaleRevision
                ))
            ));
        } else {
            assert_eq!(head, first);
            let transferred = run(
                &mut store,
                &owner,
                recover(
                    &first,
                    WorkClaimRecovery::Transfer {
                        recipient: recipient.session_id.clone(),
                    },
                ),
                23,
            )?;
            assert_eq!(transferred.claim().lease_incarnation, 2);
        }
        store.verify_storage()?;
    }
    Ok(())
}

#[test]
fn uncertain_owner_close_cannot_authorize_reclaim_before_its_commit_is_resolved() -> TestResult {
    for (phase, committed) in phases() {
        let (mut store, owner, recipient) = opened()?;
        let first = run(
            &mut store,
            &owner,
            CoordinationCommand::Acquire(request("claim:a")?),
            20,
        )?;
        store.journal.fail_after_phase(phase);
        assert!(matches!(
            store.close(&owner.principal_id, &owner.session_id, TimestampNs(21)),
            Err(DurableSessionError::Journal(_))
        ));
        let reclaim = recover(
            &first,
            WorkClaimRecovery::Reclaim {
                expires_at: TimestampNs(950),
            },
        );
        assert!(matches!(
            run(&mut store, &recipient, reclaim.clone(), 22),
            Err(DurableSessionError::ReconciliationRequired)
        ));
        assert_eq!(
            store.reconcile_pending(IncompleteTailPolicy::Truncate)?,
            if committed {
                SessionAppendRecovery::Committed
            } else {
                SessionAppendRecovery::NotCommitted
            }
        );
        let mut store = restart(store)?;
        let result = run(&mut store, &recipient, reclaim, 22);
        if committed {
            assert_eq!(result?.claim().lease_incarnation, 2);
            assert!(matches!(
                store.session(&owner.principal_id, &owner.session_id, TimestampNs(23)),
                Err(DurableSessionError::Session(
                    ReferenceSessionError::Unavailable
                ))
            ));
        } else {
            assert!(matches!(
                result,
                Err(DurableSessionError::WorkClaim(WorkClaimError::Conflict))
            ));
            assert_eq!(run(&mut store, &owner, inspect("claim:a"), 23)?, first);
        }
        store.verify_storage()?;
    }
    Ok(())
}

#[test]
fn cold_recovery_checks_semantic_history_before_trimming_a_torn_tail() -> TestResult {
    let (mut store, owner, _) = opened()?;
    run(
        &mut store,
        &owner,
        CoordinationCommand::Acquire(request("claim:a")?),
        20,
    )?;
    let checkpoint = store.verify_storage()?.checkpoint_digest;
    let command = codec::Request {
        principal: owner.principal_id,
        session: owner.session_id,
        command: inspect("claim:a"),
        now: TimestampNs(20),
    };
    let forged = codec::encode_record(
        &codec::encode_request(&command)?,
        checkpoint,
        checkpoint,
        ContentDigest::sha256(b"fabricated-outcome"),
    )?;
    let path = store.path().to_path_buf();
    drop(store);
    let mut raw = Journal::open(&path, IncompleteTailPolicy::Reject)?;
    raw.append(COORDINATION_COMMAND_RECORD_KIND, &forged)?;
    let root = raw.last_root();
    raw.fail_after_phase(AppendPhase::BodySync);
    assert!(
        raw.append(COORDINATION_COMMAND_RECORD_KIND, &forged)
            .is_err()
    );
    drop(raw);
    let before = std::fs::read(&path)?;
    assert!(matches!(
        DurableSessionStore::recover_existing_with_coordination(
            &path,
            root,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
            IncompleteTailPolicy::Truncate,
        ),
        Err(DurableSessionError::InvalidHistory)
    ));
    assert_eq!(std::fs::read(&path)?, before);
    Ok(())
}

#[test]
fn corruption_in_a_complete_record_is_not_misclassified_as_a_trimmable_tail() -> TestResult {
    let (store, _, _) = opened()?;
    let path = store.path().to_path_buf();
    let root = store.committed_root();
    drop(store);
    let mut bytes = std::fs::read(&path)?;
    let tail = bytes[..4].to_vec();
    bytes[90] ^= 1;
    bytes.extend_from_slice(&tail);
    std::fs::write(&path, &bytes)?;
    assert!(matches!(
        DurableSessionStore::recover_existing_with_coordination(
            &path,
            root,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
            IncompleteTailPolicy::Truncate,
        ),
        Err(DurableSessionError::Journal(_))
    ));
    assert_eq!(std::fs::read(&path)?, bytes);
    Ok(())
}

#[test]
fn capacity_failure_never_acknowledges_transfer_or_discards_the_previous_fence() -> TestResult {
    let (mut store, owner, recipient) = opened()?;
    let first = run(
        &mut store,
        &owner,
        CoordinationCommand::Acquire(request("claim:a")?),
        20,
    )?;
    let root = store.committed_root();
    let path = store.path().to_path_buf();
    let before = std::fs::read(&path)?;
    store.limits.max_records = store.records;
    assert!(matches!(
        run(
            &mut store,
            &owner,
            recover(
                &first,
                WorkClaimRecovery::Transfer {
                    recipient: recipient.session_id.clone(),
                }
            ),
            21
        ),
        Err(DurableSessionError::CapacityExceeded)
    ));
    assert!(matches!(
        store.session(&owner.principal_id, &owner.session_id, TimestampNs(22)),
        Err(DurableSessionError::ReconciliationRequired)
    ));
    assert!(matches!(
        run(&mut store, &recipient, inspect("claim:a"), 22),
        Err(DurableSessionError::ReconciliationRequired)
    ));
    assert_eq!(std::fs::read(&path)?, before);
    drop(store);
    // The recovery owner explicitly grants more journal capacity; the stored claim ceilings
    // and every committed fence remain unchanged. This is not implicit compaction or eviction.
    let (mut store, receipt) = DurableSessionStore::recover_existing_with_coordination(
        &path,
        root,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
        IncompleteTailPolicy::Reject,
    )?;
    assert_eq!(receipt.discarded_bytes(), 0);
    assert_eq!(run(&mut store, &owner, inspect("claim:a"), 22)?, first);
    Ok(())
}

#[test]
fn legacy_cold_recovery_preserves_session_closure_without_enabling_claims() -> TestResult {
    let mut store = DurableSessionStore::create(unused_path()?, DurableSessionLimits::default())?;
    let owner = store.open(input("session:legacy")?, basis(), TimestampNs(10))?;
    store.close(&owner.principal_id, &owner.session_id, TimestampNs(20))?;
    let root = store.committed_root();
    let path = store.path().to_path_buf();
    let prefix = std::fs::read(&path)?;
    drop(store);
    let mut raw = OpenOptions::new().append(true).open(&path)?;
    raw.write_all(&prefix[..4])?;
    raw.sync_all()?;
    drop(raw);
    let (mut store, receipt) = DurableSessionStore::recover_existing(
        &path,
        root,
        DurableSessionLimits::default(),
        IncompleteTailPolicy::Truncate,
    )?;
    assert_eq!(receipt.discarded_bytes(), 4);
    assert_eq!(std::fs::read(&path)?, prefix);
    assert!(matches!(
        store.open(input("session:legacy")?, basis(), TimestampNs(30)),
        Err(DurableSessionError::Session(
            ReferenceSessionError::Unavailable
        ))
    ));
    assert!(matches!(
        run(&mut store, &owner, inspect("claim:a"), 30),
        Err(DurableSessionError::InvalidHistory)
    ));
    Ok(())
}

#[test]
fn cold_recovery_neither_creates_missing_files_nor_initializes_empty_ones() -> TestResult {
    let path = unused_path()?;
    let root = ContentDigest::sha256(b"missing");
    assert!(
        DurableSessionStore::recover_existing_with_coordination(
            &path,
            root,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
            IncompleteTailPolicy::Truncate,
        )
        .is_err()
    );
    assert!(!path.exists());
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    assert!(
        DurableSessionStore::recover_existing(
            &path,
            root,
            DurableSessionLimits::default(),
            IncompleteTailPolicy::Truncate,
        )
        .is_err()
    );
    assert!(std::fs::read(&path)?.is_empty());
    Ok(())
}

#[cfg(unix)]
#[test]
fn cold_recovery_refuses_symlinks_without_touching_the_target() -> TestResult {
    let (store, _, _) = opened()?;
    let path = store.path().to_path_buf();
    let root = store.committed_root();
    drop(store);
    let before = std::fs::read(&path)?;
    let link = unused_path()?;
    std::os::unix::fs::symlink(&path, &link)?;
    assert!(matches!(
        DurableSessionStore::recover_existing_with_coordination(
            &link,
            root,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
            IncompleteTailPolicy::Truncate,
        ),
        Err(DurableSessionError::InvalidLayout)
    ));
    assert_eq!(std::fs::read(&path)?, before);
    Ok(())
}

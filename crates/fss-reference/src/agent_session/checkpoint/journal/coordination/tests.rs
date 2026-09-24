#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{AgentSession, AgentSessionParams, CaseId};
use fss_ledger::{IncompleteTailPolicy, Journal};

use super::super::super::tests::{basis, params};
use super::*;
use crate::agent_session::work_claims::CAPABILITY_WORK_CLAIM;
use crate::agent_session::{ReferenceSessionError, SessionRefresh};

type TestResult = Result<(), Box<dyn Error>>;
static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

fn unused_path() -> Result<PathBuf, Box<dyn Error>> {
    for _ in 0..128 {
        let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fss-coordination-{}-{serial}.journal",
            std::process::id()
        ));
        if !path.exists() {
            return Ok(path);
        }
    }
    Err("coordination test path capacity exhausted".into())
}

fn input(id: &str) -> Result<AgentSessionParams, Box<dyn Error>> {
    let mut input = params()?;
    input.session_id = SessionId::parse(id)?;
    input.capabilities.insert(CAPABILITY_WORK_CLAIM.to_owned());
    Ok(input)
}

fn opened() -> Result<(DurableSessionStore, AgentSession, AgentSession), Box<dyn Error>> {
    let mut store = DurableSessionStore::create(unused_path()?, DurableSessionLimits::default())?;
    store.enable_coordination(WorkClaimLimits::default())?;
    let owner = store.open(input("session:one")?, basis(), TimestampNs(10))?;
    let recipient = store.open(input("session:two")?, basis(), TimestampNs(10))?;
    Ok((store, owner, recipient))
}

fn request(id: &str) -> Result<WorkClaimRequest, Box<dyn Error>> {
    Ok(WorkClaimRequest {
        claim_id: id.to_owned(),
        case_id: CaseId::parse("case:incident")?,
        work_root: ContentDigest::sha256(id.as_bytes()),
        privacy_class: "private:property".to_owned(),
        expires_at: TimestampNs(900),
        dependencies: BTreeSet::new(),
    })
}

fn run(
    store: &mut DurableSessionStore,
    session: &AgentSession,
    command: CoordinationCommand,
    at: i128,
) -> Result<WorkClaimRevision, DurableSessionError> {
    store.coordinate(
        &session.principal_id,
        &session.session_id,
        command,
        TimestampNs(at),
    )
}

fn update(head: &WorkClaimRevision, change: WorkClaimUpdate) -> CoordinationCommand {
    CoordinationCommand::Update {
        claim_id: head.claim().claim_id.clone(),
        expected: head.digest(),
        change,
    }
}

fn recover(head: &WorkClaimRevision, recovery: WorkClaimRecovery) -> CoordinationCommand {
    CoordinationCommand::Recover {
        claim_id: head.claim().claim_id.clone(),
        expected: head.digest(),
        recovery,
    }
}

fn inspect(id: &str) -> CoordinationCommand {
    CoordinationCommand::Inspect {
        claim_id: id.to_owned(),
    }
}

fn restart(store: DurableSessionStore) -> Result<DurableSessionStore, DurableSessionError> {
    let root = store.committed_root();
    let path = store.path().to_path_buf();
    let limits = store.limits;
    drop(store);
    DurableSessionStore::open_existing_with_coordination(
        path,
        root,
        limits,
        WorkClaimLimits::default(),
    )
}

#[test]
fn restart_preserves_transfer_progress_history_and_stale_owner_fence() -> TestResult {
    let (mut store, owner, recipient) = opened()?;
    let first = run(
        &mut store,
        &owner,
        CoordinationCommand::Acquire(request("claim:a")?),
        20,
    )?;
    let active = run(
        &mut store,
        &owner,
        update(&first, WorkClaimUpdate::Activate),
        21,
    )?;
    let progress = run(
        &mut store,
        &owner,
        update(
            &active,
            WorkClaimUpdate::Progress(ContentDigest::sha256(b"progress")),
        ),
        22,
    )?;
    let handed = run(
        &mut store,
        &owner,
        recover(
            &progress,
            WorkClaimRecovery::Transfer {
                recipient: recipient.session_id.clone(),
            },
        ),
        23,
    )?;
    let before = store.verify_storage()?;
    let mut store = restart(store)?;
    assert_eq!(store.verify_storage()?, before);
    assert_eq!(run(&mut store, &recipient, inspect("claim:a"), 24)?, handed);
    assert_eq!(handed.claim().lease_incarnation, 2);
    assert_eq!(handed.claim().progress_json, progress.claim().progress_json);
    assert!(matches!(
        run(
            &mut store,
            &owner,
            update(&handed, WorkClaimUpdate::Activate),
            25
        ),
        Err(DurableSessionError::WorkClaim(
            WorkClaimError::StaleRevision
        ))
    ));
    assert_eq!(
        run(
            &mut store,
            &recipient,
            CoordinationCommand::InspectRevision {
                claim_id: "claim:a".to_owned(),
                revision: first.digest()
            },
            26
        )?,
        first
    );
    store.verify_storage()?;
    Ok(())
}

#[test]
fn exact_acquire_retry_after_restart_never_resets_progress_or_renews() -> TestResult {
    let (mut store, owner, _) = opened()?;
    let opening = request("claim:a")?;
    let first = run(
        &mut store,
        &owner,
        CoordinationCommand::Acquire(opening.clone()),
        20,
    )?;
    let active = run(
        &mut store,
        &owner,
        update(&first, WorkClaimUpdate::Activate),
        21,
    )?;
    let mut store = restart(store)?;
    assert_eq!(
        run(
            &mut store,
            &owner,
            CoordinationCommand::Acquire(opening),
            22
        )?,
        active
    );
    assert_eq!(active.claim().expires_at_ns, 900);
    Ok(())
}

#[test]
fn owner_closure_and_orphan_reclaim_share_the_same_recoverable_history() -> TestResult {
    let (mut store, owner, recipient) = opened()?;
    let first = run(
        &mut store,
        &owner,
        CoordinationCommand::Acquire(request("claim:a")?),
        20,
    )?;
    store.close(&owner.principal_id, &owner.session_id, TimestampNs(21))?;
    let mut store = restart(store)?;
    let reclaimed = run(
        &mut store,
        &recipient,
        recover(
            &first,
            WorkClaimRecovery::Reclaim {
                expires_at: TimestampNs(950),
            },
        ),
        22,
    )?;
    assert_eq!(reclaimed.claim().lease_incarnation, 2);
    let mut store = restart(store)?;
    assert_eq!(
        run(&mut store, &recipient, inspect("claim:a"), 23)?,
        reclaimed
    );
    assert!(matches!(
        store.open(input("session:one")?, basis(), TimestampNs(24)),
        Err(DurableSessionError::Session(
            ReferenceSessionError::Unavailable
        ))
    ));
    Ok(())
}

#[test]
fn failed_work_read_persists_the_global_clock_watermark() -> TestResult {
    let (mut store, owner, recipient) = opened()?;
    let first = run(
        &mut store,
        &owner,
        CoordinationCommand::Acquire(request("claim:a")?),
        20,
    )?;
    let before = store.committed_root();
    assert!(matches!(
        run(&mut store, &owner, inspect("claim:missing"), 500),
        Err(DurableSessionError::WorkClaim(WorkClaimError::Unavailable))
    ));
    assert_ne!(store.committed_root(), before);
    let mut store = restart(store)?;
    assert!(matches!(
        run(&mut store, &recipient, inspect("claim:a"), 499),
        Err(DurableSessionError::WorkClaim(
            WorkClaimError::ClockRegression
        ))
    ));
    assert_eq!(run(&mut store, &recipient, inspect("claim:a"), 500)?, first);
    Ok(())
}

#[test]
fn failed_work_read_persists_session_expiry_tombstones() -> TestResult {
    let (mut store, owner, _) = opened()?;
    run(
        &mut store,
        &owner,
        CoordinationCommand::Acquire(request("claim:a")?),
        20,
    )?;
    assert!(matches!(
        run(&mut store, &owner, inspect("claim:a"), 1_000),
        Err(DurableSessionError::WorkClaim(WorkClaimError::Session(
            ReferenceSessionError::Unavailable
        )))
    ));
    let mut store = restart(store)?;
    assert!(matches!(
        store.open(input("session:one")?, basis(), TimestampNs(10)),
        Err(DurableSessionError::Session(
            ReferenceSessionError::Unavailable
        ))
    ));
    Ok(())
}

#[test]
fn completed_dependency_and_terminal_scope_reservation_survive_restart() -> TestResult {
    let (mut store, owner, recipient) = opened()?;
    let dep = run(
        &mut store,
        &owner,
        CoordinationCommand::Acquire(request("claim:dep")?),
        20,
    )?;
    let mut child = request("claim:child")?;
    child.dependencies.insert("claim:dep".to_owned());
    let child = run(
        &mut store,
        &recipient,
        CoordinationCommand::Acquire(child),
        21,
    )?;
    assert!(matches!(
        run(
            &mut store,
            &recipient,
            update(&child, WorkClaimUpdate::Activate),
            22
        ),
        Err(DurableSessionError::WorkClaim(
            WorkClaimError::DependencyPending
        ))
    ));
    let dep = run(
        &mut store,
        &owner,
        update(&dep, WorkClaimUpdate::Activate),
        23,
    )?;
    let done = run(
        &mut store,
        &owner,
        update(
            &dep,
            WorkClaimUpdate::Complete(ContentDigest::sha256(b"result")),
        ),
        24,
    )?;
    let mut store = restart(store)?;
    run(
        &mut store,
        &recipient,
        update(&child, WorkClaimUpdate::Activate),
        25,
    )?;
    assert!(matches!(
        run(
            &mut store,
            &recipient,
            recover(
                &done,
                WorkClaimRecovery::Reclaim {
                    expires_at: TimestampNs(950)
                }
            ),
            26
        ),
        Err(DurableSessionError::WorkClaim(
            WorkClaimError::InvalidTransition
        ))
    ));
    let mut replacement = request("claim:replacement")?;
    replacement.work_root = ContentDigest::sha256(b"claim:dep");
    assert!(matches!(
        run(
            &mut store,
            &owner,
            CoordinationCommand::Acquire(replacement),
            27
        ),
        Err(DurableSessionError::WorkClaim(WorkClaimError::Conflict))
    ));
    Ok(())
}

#[test]
fn session_only_readers_cannot_silently_discard_claim_history() -> TestResult {
    let (store, _, _) = opened()?;
    let path = store.path().to_path_buf();
    let root = store.committed_root();
    drop(store);
    assert!(matches!(
        DurableSessionStore::open_existing(&path, root, DurableSessionLimits::default()),
        Err(DurableSessionError::InvalidHistory)
    ));
    assert!(matches!(
        DurableSessionStore::inspect(&path, DurableSessionLimits::default()),
        Err(DurableSessionError::InvalidHistory)
    ));
    let store = DurableSessionStore::open_existing_with_coordination(
        path,
        root,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?;
    store.verify_storage()?;
    Ok(())
}

#[test]
fn stored_limits_are_not_widened_and_initialization_cannot_reset_fences() -> TestResult {
    let (mut store, _, _) = opened()?;
    let before = store.verify_storage()?;
    store.enable_coordination(WorkClaimLimits::default())?;
    assert_eq!(store.verify_storage()?, before);
    assert!(matches!(
        store.enable_coordination(WorkClaimLimits {
            max_claims: 2,
            ..WorkClaimLimits::default()
        }),
        Err(DurableSessionError::InvalidHistory)
    ));
    let path = store.path().to_path_buf();
    let root = store.committed_root();
    drop(store);
    assert!(matches!(
        DurableSessionStore::open_existing_with_coordination(
            &path,
            root,
            DurableSessionLimits::default(),
            WorkClaimLimits {
                max_claims: 2,
                ..WorkClaimLimits::default()
            }
        ),
        Err(DurableSessionError::CapacityExceeded)
    ));
    let mut raw = Journal::open(&path, IncompleteTailPolicy::Reject)?;
    raw.append(
        COORDINATION_INIT_RECORD_KIND,
        &codec::encode_initialization(WorkClaimLimits::default(), before.checkpoint_digest)?,
    )?;
    drop(raw);
    assert!(matches!(
        DurableSessionStore::inspect_with_coordination(
            path,
            DurableSessionLimits::default(),
            WorkClaimLimits::default()
        ),
        Err(DurableSessionError::InvalidHistory)
    ));
    Ok(())
}

#[test]
fn hash_valid_fabricated_result_is_rejected_by_semantic_replay() -> TestResult {
    let (mut store, owner, _) = opened()?;
    run(
        &mut store,
        &owner,
        CoordinationCommand::Acquire(request("claim:a")?),
        20,
    )?;
    let inspection = store.verify_storage()?;
    let command = codec::Request {
        principal: owner.principal_id,
        session: owner.session_id,
        command: inspect("claim:a"),
        now: TimestampNs(20),
    };
    let payload = codec::encode_record(
        &codec::encode_request(&command)?,
        inspection.checkpoint_digest,
        inspection.checkpoint_digest,
        ContentDigest::sha256(b"fabricated-success"),
    )?;
    let path = store.path().to_path_buf();
    drop(store);
    let mut raw = Journal::open(&path, IncompleteTailPolicy::Reject)?;
    raw.append(COORDINATION_COMMAND_RECORD_KIND, &payload)?;
    drop(raw);
    assert!(matches!(
        DurableSessionStore::inspect_with_coordination(
            path,
            DurableSessionLimits::default(),
            WorkClaimLimits::default()
        ),
        Err(DurableSessionError::InvalidHistory)
    ));
    Ok(())
}

#[test]
fn revoked_grants_still_gate_restored_ownership() -> TestResult {
    let (mut store, owner, _) = opened()?;
    let first = run(
        &mut store,
        &owner,
        CoordinationCommand::Acquire(request("claim:a")?),
        20,
    )?;
    let mut grants = owner.capabilities.clone();
    grants.remove(CAPABILITY_WORK_CLAIM);
    store.refresh(
        &owner.principal_id,
        &owner.session_id,
        SessionRefresh {
            expected_session_digest: owner.session_digest(),
            current_anchor: owner.current_anchor.clone(),
            capabilities: grants,
            privacy_scope: owner.privacy_scope.clone(),
        },
        TimestampNs(21),
    )?;
    let mut store = restart(store)?;
    assert!(matches!(
        run(
            &mut store,
            &owner,
            update(&first, WorkClaimUpdate::Activate),
            22
        ),
        Err(DurableSessionError::WorkClaim(WorkClaimError::Session(
            ReferenceSessionError::GrantEscalation
        )))
    ));
    store.verify_storage()?;
    Ok(())
}

#[test]
fn every_command_variant_roundtrips_and_every_truncated_record_is_refused() -> TestResult {
    let digest = ContentDigest::sha256(b"expected");
    let mut commands = vec![
        CoordinationCommand::Acquire(request("claim:a")?),
        inspect("claim:a"),
        CoordinationCommand::InspectRevision {
            claim_id: "claim:a".to_owned(),
            revision: digest,
        },
    ];
    for change in [
        WorkClaimUpdate::Activate,
        WorkClaimUpdate::Block(digest),
        WorkClaimUpdate::Progress(digest),
        WorkClaimUpdate::Complete(digest),
        WorkClaimUpdate::Release,
        WorkClaimUpdate::Renew(TimestampNs(950)),
    ] {
        commands.push(CoordinationCommand::Update {
            claim_id: "claim:a".to_owned(),
            expected: digest,
            change,
        });
    }
    for recovery in [
        WorkClaimRecovery::Expire,
        WorkClaimRecovery::Transfer {
            recipient: SessionId::parse("session:two")?,
        },
        WorkClaimRecovery::Reclaim {
            expires_at: TimestampNs(950),
        },
    ] {
        commands.push(CoordinationCommand::Recover {
            claim_id: "claim:a".to_owned(),
            expected: digest,
            recovery,
        });
    }
    for command in commands {
        let request = codec::Request {
            principal: PrincipalId::parse("principal:owner")?,
            session: SessionId::parse("session:one")?,
            command: command.clone(),
            now: TimestampNs(20),
        };
        let bytes =
            codec::encode_record(&codec::encode_request(&request)?, digest, digest, digest)?;
        let decoded = codec::decode_record(&bytes)?;
        assert_eq!(decoded.request.command, command);
        assert_eq!(decoded.request.principal, request.principal);
        assert_eq!(decoded.request.session, request.session);
        assert_eq!(decoded.request.now, request.now);
        for end in 0..bytes.len() {
            assert!(
                codec::decode_record(&bytes[..end]).is_err(),
                "accepted cut at {end}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(codec::decode_record(&trailing).is_err());
    }
    Ok(())
}

#[test]
fn oversized_command_is_refused_before_session_clock_or_storage_changes() -> TestResult {
    let (mut store, owner, _) = opened()?;
    let before = store.verify_storage()?;
    assert!(matches!(
        run(&mut store, &owner, inspect(&"x".repeat(129)), 800),
        Err(DurableSessionError::CapacityExceeded)
    ));
    assert_eq!(store.verify_storage()?, before);
    run(
        &mut store,
        &owner,
        CoordinationCommand::Acquire(request("claim:a")?),
        20,
    )?;
    Ok(())
}

#[test]
fn refreshed_anchor_never_silently_rebases_recovered_work() -> TestResult {
    let (mut store, owner, _) = opened()?;
    let first = run(
        &mut store,
        &owner,
        CoordinationCommand::Acquire(request("claim:a")?),
        20,
    )?;
    let mut next_anchor = owner.current_anchor.clone();
    next_anchor.commit_sequence += 1;
    store.refresh(
        &owner.principal_id,
        &owner.session_id,
        SessionRefresh {
            expected_session_digest: owner.session_digest(),
            current_anchor: next_anchor,
            capabilities: owner.capabilities.clone(),
            privacy_scope: owner.privacy_scope.clone(),
        },
        TimestampNs(21),
    )?;
    let mut store = restart(store)?;
    assert!(matches!(
        run(
            &mut store,
            &owner,
            update(&first, WorkClaimUpdate::Activate),
            22
        ),
        Err(DurableSessionError::WorkClaim(WorkClaimError::StaleBasis))
    ));
    assert_eq!(run(&mut store, &owner, inspect("claim:a"), 23)?, first);
    store.verify_storage()?;
    Ok(())
}

mod recovery;

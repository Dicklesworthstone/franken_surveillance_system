#![forbid(unsafe_code)]

use super::*;

#[test]
fn transfer_fences_the_old_owner_and_preserves_progress_without_renewing() -> TestResult {
    let mut f = Fixture::new()?;
    let initial = f.acquire(request("claim:one", "work")?, 2)?;
    let active = f.update(&initial, WorkClaimUpdate::Activate, 3)?;
    let progress = f.update(
        &active,
        WorkClaimUpdate::Progress(ContentDigest::sha256(b"pending-reconciliation")),
        4,
    )?;
    let moved = f.claims.recover(
        &mut f.sessions,
        &f.owner,
        &f.alice,
        &progress,
        WorkClaimRecovery::Transfer {
            recipient: f.bob.clone(),
        },
        TimestampNs(5),
    )?;
    assert_eq!(moved.claim().owner_session_id, f.bob.as_str());
    assert_eq!(moved.claim().lease_incarnation, 2);
    assert_eq!(moved.claim().state, WorkClaimState::Claimed);
    assert_eq!(moved.claim().expires_at_ns, progress.claim().expires_at_ns);
    assert_eq!(moved.claim().progress_json, progress.claim().progress_json);
    assert_eq!(moved.predecessor(), Some(progress.digest()));
    assert!(matches!(
        f.update(&progress, WorkClaimUpdate::Release, 6),
        Err(WorkClaimError::StaleRevision)
    ));
    assert!(matches!(
        f.update(&moved, WorkClaimUpdate::Release, 6),
        Err(WorkClaimError::StaleRevision)
    ));
    let resumed = f.claims.update(
        &mut f.sessions,
        &f.owner,
        &f.bob,
        &moved,
        WorkClaimUpdate::Activate,
        TimestampNs(6),
    )?;
    assert_eq!(resumed.claim().state, WorkClaimState::Active);
    Ok(())
}

#[test]
fn transfer_checks_recipient_authority_and_shortens_to_recipient_expiry() -> TestResult {
    let mut f = Fixture::new()?;
    let head = f.acquire(request("claim:one", "work")?, 2)?;
    let mut input = params("session:short")?;
    input.expires_at_ns = 50;
    let short = f.sessions.open(input, basis(), TimestampNs(2))?;
    let moved = f.claims.recover(
        &mut f.sessions,
        &f.owner,
        &f.alice,
        &head,
        WorkClaimRecovery::Transfer {
            recipient: short.session_id,
        },
        TimestampNs(3),
    )?;
    assert_eq!(moved.claim().expires_at_ns, 50);
    let head = f.acquire(request("claim:other", "other")?, 4)?;
    let mut input = params("session:foreign")?;
    input.principal_id = PrincipalId::parse("principal:foreign")?;
    let foreign = f.sessions.open(input, basis(), TimestampNs(4))?;
    assert!(
        f.claims
            .recover(
                &mut f.sessions,
                &f.owner,
                &f.alice,
                &head,
                WorkClaimRecovery::Transfer {
                    recipient: foreign.session_id
                },
                TimestampNs(5)
            )
            .is_err()
    );
    assert_eq!(f.claims.claims["claim:other"].head, head);
    Ok(())
}

#[test]
fn expiry_is_explicit_retained_idempotent_and_reclaimed_with_a_higher_fence() -> TestResult {
    let mut f = Fixture::new()?;
    let head = f.acquire(request("claim:one", "work")?, 2)?;
    assert!(matches!(
        f.claims.recover(
            &mut f.sessions,
            &f.owner,
            &f.bob,
            &head,
            WorkClaimRecovery::Expire,
            TimestampNs(99)
        ),
        Err(WorkClaimError::InvalidLease)
    ));
    let expired = f.claims.recover(
        &mut f.sessions,
        &f.owner,
        &f.bob,
        &head,
        WorkClaimRecovery::Expire,
        TimestampNs(100),
    )?;
    assert_eq!(expired.claim().state, WorkClaimState::Expired);
    let repeated = f.claims.recover(
        &mut f.sessions,
        &f.owner,
        &f.bob,
        &expired,
        WorkClaimRecovery::Expire,
        TimestampNs(101),
    )?;
    assert_eq!(repeated, expired);
    assert_eq!(f.claims.revisions, 2);
    let reclaimed = f.claims.recover(
        &mut f.sessions,
        &f.owner,
        &f.bob,
        &expired,
        WorkClaimRecovery::Reclaim {
            expires_at: TimestampNs(200),
        },
        TimestampNs(102),
    )?;
    assert_eq!(reclaimed.claim().lease_incarnation, 2);
    assert_eq!(reclaimed.claim().owner_session_id, f.bob.as_str());
    assert_eq!(reclaimed.predecessor(), Some(expired.digest()));
    assert!(matches!(
        f.update(&head, WorkClaimUpdate::Activate, 103),
        Err(WorkClaimError::StaleRevision)
    ));
    Ok(())
}

#[test]
fn live_lease_cannot_be_stolen_but_closed_owner_can_be_recovered() -> TestResult {
    let mut f = Fixture::new()?;
    let head = f.acquire(request("claim:one", "work")?, 2)?;
    assert!(matches!(
        f.claims.recover(
            &mut f.sessions,
            &f.owner,
            &f.bob,
            &head,
            WorkClaimRecovery::Reclaim {
                expires_at: TimestampNs(200)
            },
            TimestampNs(3)
        ),
        Err(WorkClaimError::Conflict)
    ));
    f.sessions.close(&f.owner, &f.alice, TimestampNs(4))?;
    let reclaimed = f.claims.recover(
        &mut f.sessions,
        &f.owner,
        &f.bob,
        &head,
        WorkClaimRecovery::Reclaim {
            expires_at: TimestampNs(200),
        },
        TimestampNs(5),
    )?;
    assert_eq!(reclaimed.claim().lease_incarnation, 2);
    assert_eq!(reclaimed.claim().owner_session_id, f.bob.as_str());
    assert!(matches!(
        f.update(&reclaimed, WorkClaimUpdate::Release, 6),
        Err(WorkClaimError::Session(_))
    ));
    Ok(())
}

#[test]
fn missing_owner_state_is_not_an_orphan_certificate() -> TestResult {
    let mut f = Fixture::new()?;
    let head = f.acquire(request("claim:one", "work")?, 2)?;
    // Simulate a lost/incomplete session authority, not a legitimate close operation.
    f.sessions.sessions.remove(&f.alice);
    assert!(matches!(
        f.claims.recover(
            &mut f.sessions,
            &f.owner,
            &f.bob,
            &head,
            WorkClaimRecovery::Reclaim {
                expires_at: TimestampNs(200)
            },
            TimestampNs(3)
        ),
        Err(WorkClaimError::Unavailable)
    ));
    assert_eq!(f.claims.revisions, 1);
    Ok(())
}

#[test]
fn released_work_reclaims_but_completed_results_never_reopen() -> TestResult {
    let mut f = Fixture::new()?;
    let head = f.acquire(request("claim:one", "work")?, 2)?;
    let released = f.update(&head, WorkClaimUpdate::Release, 3)?;
    let recovered = f.claims.recover(
        &mut f.sessions,
        &f.owner,
        &f.bob,
        &released,
        WorkClaimRecovery::Reclaim {
            expires_at: TimestampNs(200),
        },
        TimestampNs(4),
    )?;
    let active = f.claims.update(
        &mut f.sessions,
        &f.owner,
        &f.bob,
        &recovered,
        WorkClaimUpdate::Activate,
        TimestampNs(5),
    )?;
    let done = f.claims.update(
        &mut f.sessions,
        &f.owner,
        &f.bob,
        &active,
        WorkClaimUpdate::Complete(ContentDigest::sha256(b"result")),
        TimestampNs(6),
    )?;
    for recovery in [
        WorkClaimRecovery::Expire,
        WorkClaimRecovery::Reclaim {
            expires_at: TimestampNs(300),
        },
    ] {
        assert!(matches!(
            f.claims.recover(
                &mut f.sessions,
                &f.owner,
                &f.alice,
                &done,
                recovery,
                TimestampNs(201)
            ),
            Err(WorkClaimError::InvalidTransition)
        ));
    }
    assert_eq!(f.claims.claims["claim:one"].head, done);
    Ok(())
}

#[test]
fn competing_orphan_recovery_and_capacity_failure_are_atomic() -> TestResult {
    let mut f = Fixture::new()?;
    let head = f.acquire(request("claim:one", "work")?, 2)?;
    f.claims.limits.max_revisions = 1;
    assert!(matches!(
        f.claims.recover(
            &mut f.sessions,
            &f.owner,
            &f.bob,
            &head,
            WorkClaimRecovery::Reclaim {
                expires_at: TimestampNs(200)
            },
            TimestampNs(100)
        ),
        Err(WorkClaimError::CapacityExceeded)
    ));
    assert_eq!(f.claims.claims["claim:one"].head, head);
    assert!(!head.lease_covers(TimestampNs(100)));
    f.claims.limits.max_revisions = 3;
    let won = f.claims.recover(
        &mut f.sessions,
        &f.owner,
        &f.bob,
        &head,
        WorkClaimRecovery::Reclaim {
            expires_at: TimestampNs(200),
        },
        TimestampNs(100),
    )?;
    assert!(matches!(
        f.claims.recover(
            &mut f.sessions,
            &f.owner,
            &f.alice,
            &head,
            WorkClaimRecovery::Reclaim {
                expires_at: TimestampNs(200)
            },
            TimestampNs(100)
        ),
        Err(WorkClaimError::StaleRevision)
    ));
    assert_eq!(f.claims.claims["claim:one"].head, won);
    Ok(())
}

#[test]
fn reclaim_preserves_pending_dependency_and_progress_instead_of_declaring_success() -> TestResult {
    let mut f = Fixture::new()?;
    f.acquire(request("claim:dependency", "dependency")?, 2)?;
    let mut input = request("claim:one", "work")?;
    input.dependencies.insert("claim:dependency".to_owned());
    let head = f.acquire(input, 3)?;
    let blocked = f.update(
        &head,
        WorkClaimUpdate::Block(ContentDigest::sha256(b"unresolved-obligation")),
        4,
    )?;
    f.sessions.close(&f.owner, &f.alice, TimestampNs(5))?;
    let recovered = f.claims.recover(
        &mut f.sessions,
        &f.owner,
        &f.bob,
        &blocked,
        WorkClaimRecovery::Reclaim {
            expires_at: TimestampNs(200),
        },
        TimestampNs(6),
    )?;
    assert_eq!(
        recovered.claim().progress_json,
        blocked.claim().progress_json
    );
    assert_eq!(recovered.claim().dependencies, blocked.claim().dependencies);
    assert!(recovered.claim().result_root.is_none());
    assert!(matches!(
        f.claims.update(
            &mut f.sessions,
            &f.owner,
            &f.bob,
            &recovered,
            WorkClaimUpdate::Activate,
            TimestampNs(7)
        ),
        Err(WorkClaimError::DependencyPending)
    ));
    Ok(())
}

#[test]
fn future_dated_owner_closure_cannot_authorize_past_takeover() -> TestResult {
    let mut f = Fixture::new()?;
    let head = f.acquire(request("claim:one", "work")?, 2)?;
    f.sessions.close(&f.owner, &f.alice, TimestampNs(80))?;
    assert!(matches!(
        f.claims.recover(
            &mut f.sessions,
            &f.owner,
            &f.bob,
            &head,
            WorkClaimRecovery::Reclaim {
                expires_at: TimestampNs(200)
            },
            TimestampNs(50)
        ),
        Err(WorkClaimError::ClockRegression)
    ));
    assert_eq!(f.claims.revisions, 1);
    let recovered = f.claims.recover(
        &mut f.sessions,
        &f.owner,
        &f.bob,
        &head,
        WorkClaimRecovery::Reclaim {
            expires_at: TimestampNs(200),
        },
        TimestampNs(80),
    )?;
    assert_eq!(recovered.claim().lease_incarnation, 2);
    Ok(())
}

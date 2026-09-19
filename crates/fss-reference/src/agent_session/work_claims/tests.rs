#![forbid(unsafe_code)]

use std::error::Error;
use fss_core::{AgentSessionParams, ContractBasisRegistryBytes, LedgerAnchor};
use super::*;

mod recovery;

type TestResult = Result<(), Box<dyn Error>>;

fn basis() -> ContractBasis {
    ContractBasis::from_registry_bytes(
        ContractBasisRegistryBytes::new(
            b"schemas", b"operations", b"views", b"capabilities", b"errors", b"costs",
            "fss-reference:work-claim-test",
        ).with_accepted_nightly("nightly-2026-08-31"),
    )
}

fn params(id: &str) -> Result<AgentSessionParams, ContractError> {
    Ok(AgentSessionParams {
        session_id: SessionId::parse(id)?,
        mission_id: MissionId::parse("mission:claims")?,
        principal_id: PrincipalId::parse("principal:owner")?,
        capabilities: BTreeSet::from([CAPABILITY_WORK_CLAIM.to_owned()]),
        privacy_scope: BTreeSet::from(["private:property".to_owned()]),
        current_anchor: LedgerAnchor::genesis("site:claims"),
        view_id: "AVIEW-001".to_owned(), token_budget: 100, symbol_table_generation: 0,
        last_acknowledged_situation_fingerprint: None,
        created_at_ns: 0, expires_at_ns: 1_000,
    })
}

fn request(id: &str, work: &str) -> Result<WorkClaimRequest, ContractError> {
    Ok(WorkClaimRequest {
        claim_id: id.to_owned(), case_id: CaseId::parse("case:test")?,
        work_root: ContentDigest::sha256(work.as_bytes()),
        privacy_class: "private:property".to_owned(), expires_at: TimestampNs(100),
        dependencies: BTreeSet::new(),
    })
}

struct Fixture {
    sessions: ReferenceSessionStore,
    claims: ReferenceWorkClaimStore,
    owner: PrincipalId,
    alice: SessionId,
    bob: SessionId,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let mut sessions = ReferenceSessionStore::default();
        let alice = sessions.open(params("session:alice")?, basis(), TimestampNs(1))?;
        let bob = sessions.open(params("session:bob")?, basis(), TimestampNs(1))?;
        Ok(Self {
            sessions, claims: ReferenceWorkClaimStore::default(),
            owner: alice.principal_id, alice: alice.session_id, bob: bob.session_id,
        })
    }

    fn acquire(&mut self, input: WorkClaimRequest, now: i128) -> Result<WorkClaimRevision, WorkClaimError> {
        self.claims.acquire(&mut self.sessions, &self.owner, &self.alice, input, TimestampNs(now))
    }

    fn update(&mut self, head: &WorkClaimRevision, update: WorkClaimUpdate, now: i128)
        -> Result<WorkClaimRevision, WorkClaimError>
    {
        self.claims.update(&mut self.sessions, &self.owner, &self.alice, head, update, TimestampNs(now))
    }
}

#[test]
fn first_committer_wins_in_both_session_orders() -> TestResult {
    for reverse in [false, true] {
        let mut f = Fixture::new()?;
        let (winner, loser) = if reverse { (&f.bob, &f.alice) } else { (&f.alice, &f.bob) };
        let claim = f.claims.acquire(&mut f.sessions, &f.owner, winner, request("claim:first", "work")?, TimestampNs(2))?;
        assert_eq!(claim.claim().owner_session_id, winner.as_str());
        assert!(matches!(f.claims.acquire(&mut f.sessions, &f.owner, loser,
            request("claim:second", "work")?, TimestampNs(2)), Err(WorkClaimError::Conflict)));
        assert_eq!(f.claims.claims.len(), 1);
        assert_eq!(f.claims.revisions, 1);
    }
    Ok(())
}

#[test]
fn opening_retry_preserves_progress_fence_and_expiry_even_at_capacity() -> TestResult {
    let mut f = Fixture::new()?;
    f.claims.limits.max_claims = 1;
    f.claims.limits.max_revisions = 3;
    let input = request("claim:one", "work")?;
    let initial = f.acquire(input.clone(), 2)?;
    let active = f.update(&initial, WorkClaimUpdate::Activate, 3)?;
    let renewed = f.update(&active, WorkClaimUpdate::Renew(TimestampNs(200)), 4)?;
    let retried = f.acquire(input.clone(), 5)?;
    assert_eq!(retried, renewed);
    assert_eq!(retried.claim().expires_at_ns, 200);
    assert_eq!(retried.claim().lease_incarnation, 2);
    assert_eq!(f.claims.revisions, 3);
    let mut changed = input;
    changed.expires_at = TimestampNs(201);
    assert!(matches!(f.acquire(changed, 6), Err(WorkClaimError::Conflict)));
    assert!(matches!(f.update(&retried, WorkClaimUpdate::Progress(ContentDigest::sha256(b"p")), 7),
        Err(WorkClaimError::CapacityExceeded)));
    assert_eq!(f.claims.claims["claim:one"].head, renewed);
    Ok(())
}

#[test]
fn stale_progress_and_nonowner_writes_do_not_overwrite_the_head() -> TestResult {
    let mut f = Fixture::new()?;
    let initial = f.acquire(request("claim:one", "work")?, 2)?;
    let active = f.update(&initial, WorkClaimUpdate::Activate, 3)?;
    assert!(matches!(f.update(&initial, WorkClaimUpdate::Release, 4), Err(WorkClaimError::StaleRevision)));
    assert!(matches!(f.claims.update(&mut f.sessions, &f.owner, &f.bob, &active,
        WorkClaimUpdate::Release, TimestampNs(4)), Err(WorkClaimError::StaleRevision)));
    let progress = f.update(&active, WorkClaimUpdate::Progress(ContentDigest::sha256(b"progress")), 5)?;
    assert_eq!(progress.predecessor(), Some(active.digest()));
    assert_eq!(progress.revision(), 3);
    assert_eq!(progress.claim().lease_incarnation, initial.claim().lease_incarnation);
    assert_ne!(progress.digest(), active.digest());
    let old = f.claims.inspect_revision(&mut f.sessions, &f.owner, &f.alice, "claim:one", initial.digest(), TimestampNs(5))?;
    assert_eq!(old, initial);
    assert!(matches!(f.update(&old, WorkClaimUpdate::Activate, 5), Err(WorkClaimError::StaleRevision)));
    Ok(())
}

#[test]
fn exact_expiry_and_backward_time_never_resurrect_a_lease() -> TestResult {
    let mut f = Fixture::new()?;
    let initial = f.acquire(request("claim:one", "work")?, 2)?;
    assert!(initial.lease_covers(TimestampNs(99)));
    assert!(!initial.lease_covers(TimestampNs(100)));
    assert!(matches!(f.update(&initial, WorkClaimUpdate::Renew(TimestampNs(200)), 100), Err(WorkClaimError::InvalidLease)));
    assert!(f.update(&initial, WorkClaimUpdate::Activate, 99).is_err());
    // A different live session cannot rewind the coordinator's clock watermark either.
    assert!(matches!(f.claims.inspect(&mut f.sessions, &f.owner, &f.bob, "claim:one", TimestampNs(99)),
        Err(WorkClaimError::ClockRegression)));
    let mut replacement = request("claim:replacement", "work")?;
    replacement.expires_at = TimestampNs(200);
    assert!(matches!(f.acquire(replacement, 101), Err(WorkClaimError::Conflict)));
    assert_eq!(f.claims.revisions, 1);
    Ok(())
}

#[test]
fn lease_duration_and_session_expiry_are_hard_bounds() -> TestResult {
    let mut f = Fixture::new()?;
    f.claims.limits.max_lease_ns = 100;
    for expiry in [0, 2, 103, 1_001, i128::MAX] {
        let mut input = request("claim:one", "work")?;
        input.expires_at = TimestampNs(expiry);
        assert!(matches!(f.acquire(input, 2), Err(WorkClaimError::InvalidLease)));
    }
    let initial = f.acquire(request("claim:one", "work")?, 2)?;
    assert!(matches!(f.update(&initial, WorkClaimUpdate::Renew(TimestampNs(100)), 3), Err(WorkClaimError::InvalidLease)));
    assert!(matches!(f.update(&initial, WorkClaimUpdate::Renew(TimestampNs(104)), 3), Err(WorkClaimError::InvalidLease)));
    assert_eq!(f.claims.revisions, 1);
    Ok(())
}

#[test]
fn dependencies_block_work_until_exact_basis_completion() -> TestResult {
    let mut f = Fixture::new()?;
    let first = f.acquire(request("claim:first", "first")?, 2)?;
    let mut second_input = request("claim:second", "second")?;
    second_input.dependencies.insert("claim:first".to_owned());
    let second = f.acquire(second_input, 3)?;
    assert!(matches!(f.update(&second, WorkClaimUpdate::Activate, 4), Err(WorkClaimError::DependencyPending)));
    let first = f.update(&first, WorkClaimUpdate::Activate, 5)?;
    let first = f.update(&first, WorkClaimUpdate::Complete(ContentDigest::sha256(b"result")), 6)?;
    assert_eq!(first.claim().state, WorkClaimState::Completed);
    assert!(first.claim().result_root.is_some());
    let second = f.update(&second, WorkClaimUpdate::Activate, 7)?;
    assert_eq!(second.claim().state, WorkClaimState::Active);
    assert!(matches!(f.update(&first, WorkClaimUpdate::Release, 8), Err(WorkClaimError::InvalidLease)));
    Ok(())
}

#[test]
fn dangling_self_and_hidden_dependencies_are_refused() -> TestResult {
    let mut f = Fixture::new()?;
    for dep in ["claim:one", "claim:missing"] {
        let mut input = request("claim:one", "work")?;
        input.dependencies.insert(dep.to_owned());
        assert!(f.acquire(input, 2).is_err());
    }
    assert!(f.claims.claims.is_empty());
    let mut hidden_params = params("session:hidden")?;
    hidden_params.privacy_scope = BTreeSet::from(["private:hidden".to_owned()]);
    let hidden = f.sessions.open(hidden_params, basis(), TimestampNs(2))?;
    let mut hidden_input = request("claim:hidden", "hidden")?;
    hidden_input.privacy_class = "private:hidden".to_owned();
    f.claims.acquire(&mut f.sessions, &f.owner, &hidden.session_id, hidden_input, TimestampNs(2))?;
    let mut input = request("claim:one", "work")?;
    input.dependencies.insert("claim:hidden".to_owned());
    assert!(matches!(f.acquire(input, 3), Err(WorkClaimError::Unavailable)));
    Ok(())
}

#[test]
fn principal_mission_privacy_and_revoked_grants_are_rechecked() -> TestResult {
    let mut f = Fixture::new()?;
    let head = f.acquire(request("claim:one", "work")?, 2)?;
    for (id, principal, mission, privacy, granted) in [
        ("session:foreign", "principal:foreign", "mission:claims", "private:property", true),
        ("session:mission", "principal:owner", "mission:other", "private:property", true),
        ("session:privacy", "principal:owner", "mission:claims", "private:other", true),
        ("session:ungranted", "principal:owner", "mission:claims", "private:property", false),
    ] {
        let mut input = params(id)?;
        input.principal_id = PrincipalId::parse(principal)?;
        input.mission_id = MissionId::parse(mission)?;
        input.privacy_scope = BTreeSet::from([privacy.to_owned()]);
        if !granted { input.capabilities.clear(); }
        let session = f.sessions.open(input, basis(), TimestampNs(2))?;
        let present = f.claims.inspect(&mut f.sessions, &session.principal_id, &session.session_id, "claim:one", TimestampNs(3));
        let absent = f.claims.inspect(&mut f.sessions, &session.principal_id, &session.session_id, "claim:missing", TimestampNs(3));
        assert_eq!(present.err().map(|e| e.to_string()), absent.err().map(|e| e.to_string()));
    }
    let current = f.sessions.session(&f.owner, &f.alice, TimestampNs(4))?;
    f.sessions.refresh(&f.owner, &f.alice, super::super::SessionRefresh {
        expected_session_digest: current.session_digest(), current_anchor: current.current_anchor,
        capabilities: BTreeSet::new(), privacy_scope: current.privacy_scope,
    }, TimestampNs(4))?;
    assert!(matches!(f.update(&head, WorkClaimUpdate::Activate, 5), Err(WorkClaimError::Session(_))));
    assert_eq!(f.claims.revisions, 1);
    Ok(())
}

#[test]
fn world_drift_refuses_mutation_but_keeps_recovery_information() -> TestResult {
    let mut f = Fixture::new()?;
    let head = f.acquire(request("claim:one", "work")?, 2)?;
    let current = f.sessions.session(&f.owner, &f.alice, TimestampNs(3))?;
    let mut new_anchor = current.current_anchor.clone();
    new_anchor.commit_sequence += 1;
    f.sessions.refresh(&f.owner, &f.alice, super::super::SessionRefresh {
        expected_session_digest: current.session_digest(), current_anchor: new_anchor,
        capabilities: current.capabilities, privacy_scope: current.privacy_scope,
    }, TimestampNs(3))?;
    assert!(matches!(f.update(&head, WorkClaimUpdate::Activate, 4), Err(WorkClaimError::StaleBasis)));
    assert_eq!(f.claims.inspect(&mut f.sessions, &f.owner, &f.alice, "claim:one", TimestampNs(4))?, head);
    Ok(())
}

#[test]
fn zero_capacity_and_malformed_input_do_not_leave_partial_reservations() -> TestResult {
    for limits in [
        WorkClaimLimits { max_claims: 0, ..WorkClaimLimits::default() },
        WorkClaimLimits { max_revisions: 0, ..WorkClaimLimits::default() },
        WorkClaimLimits { max_lease_ns: 0, ..WorkClaimLimits::default() },
    ] {
        let mut f = Fixture::new()?;
        f.claims = ReferenceWorkClaimStore::with_limits(limits);
        assert!(f.acquire(request("claim:one", "work")?, 2).is_err());
        assert!(f.claims.claims.is_empty());
        assert_eq!(f.claims.revisions, 0);
    }
    let mut f = Fixture::new()?;
    for id in ["", "bad\"id", "bad/id"] {
        assert!(f.acquire(request(id, "work")?, 2).is_err());
    }
    assert!(f.claims.claims.is_empty());
    assert_eq!(f.claims.revisions, 0);
    Ok(())
}

#[test]
fn fence_overflow_refuses_without_appending_and_claim_never_grants_effect_authority() -> TestResult {
    let mut f = Fixture::new()?;
    f.acquire(request("claim:one", "work")?, 2)?;
    // Private fault injection: public callers cannot manufacture or replace stored revisions.
    f.claims.claims.get_mut("claim:one").ok_or("missing fixture")?.head.claim.lease_incarnation = u64::MAX;
    let head = f.claims.inspect(&mut f.sessions, &f.owner, &f.alice, "claim:one", TimestampNs(3))?;
    assert!(matches!(f.update(&head, WorkClaimUpdate::Renew(TimestampNs(200)), 4), Err(WorkClaimError::CounterExhausted)));
    assert_eq!(f.claims.revisions, 1);
    assert_eq!(head.claim().try_canonical_bytes()?.last(), Some(&0));
    Ok(())
}

#[test]
fn deterministic_replay_has_identical_revision_chain() -> TestResult {
    fn run() -> Result<Vec<ContentDigest>, Box<dyn Error>> {
        let mut f = Fixture::new()?;
        let initial = f.acquire(request("claim:one", "work")?, 2)?;
        let active = f.update(&initial, WorkClaimUpdate::Activate, 3)?;
        let blocked = f.update(&active, WorkClaimUpdate::Block(ContentDigest::sha256(b"blocked")), 4)?;
        let resumed = f.update(&blocked, WorkClaimUpdate::Activate, 5)?;
        let completed = f.update(&resumed, WorkClaimUpdate::Complete(ContentDigest::sha256(b"result")), 6)?;
        Ok([initial, active, blocked, resumed, completed].iter().map(WorkClaimRevision::digest).collect())
    }
    assert_eq!(run()?, run()?);
    Ok(())
}

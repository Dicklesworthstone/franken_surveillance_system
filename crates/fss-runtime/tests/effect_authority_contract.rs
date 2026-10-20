#![forbid(unsafe_code)]
//! Effect tokens retain their preparing authority, issuing registry and canonical obligation.

use std::collections::BTreeSet;
use std::error::Error;

use fss_core::{
    BudgetVector, ContentDigest, EffectState, IdempotencyKey, ObligationState, OperationId,
    RegionId, RegionKind, RegionTree, RootAuthoritySpec, RuntimeGrant, TimestampNs,
};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::effect::{
    CommitApproval, CommittedEffect, EffectCoordError, EffectCoordinator, EffectTransitionError,
    PrepareSpec, PreparedEffect,
};
use fss_runtime::grant::GrantError;
use fss_runtime::lease::{LeaseError, LeaseRegistry, LeaseState};
use fss_runtime::obligation::ObligationTerminal;

type Test<T = ()> = Result<T, Box<dyn Error>>;
const RESOURCE: &str = "device:ptz:porch";
const PTZ: [RuntimeGrant; 2] = [RuntimeGrant::PtzPrepare, RuntimeGrant::PtzCommit];
const PREDICATE: &str = "camera reached the requested bounded pose";

fn budget() -> Test<BudgetVector> {
    Ok(BudgetVector::builder()
        .tokens(128)
        .bytes(8192)
        .cpu_millis(1000)
        .build()?)
}

fn spec(
    name: &str,
    grants: &[RuntimeGrant],
    deadline: Option<TimestampNs>,
) -> Test<RootAuthoritySpec> {
    Ok(RootAuthoritySpec {
        trace_id: "trace:effect-contract".into(),
        operation_id: OperationId::parse(format!("operation:scope-{name}"))?,
        principal: "principal:owner".into(),
        capabilities: grants
            .iter()
            .map(|grant| grant.as_str().to_owned())
            .collect(),
        deadline,
        priority: 10,
        budgets: budget()?,
        privacy_scope: "privacy:local".into(),
        retention_scope: "retention:approved".into(),
        anchor_universe: ContentDigest::sha256(b"effect contract fixture"),
        generation: 1,
    })
}

fn prepare_spec<'a>(operation: &'a OperationId, fence: u64) -> Test<PrepareSpec<'a>> {
    Ok(PrepareSpec {
        operation,
        idempotency_key: IdempotencyKey::parse(operation.as_str())?,
        request_digest: ContentDigest::sha256(operation.as_str().as_bytes()),
        precondition_digest: preconditions(),
        resource: RESOURCE,
        fence,
        prepare_grant: PTZ[0],
        commit_grant: PTZ[1],
        terminal_predicate: PREDICATE,
    })
}

fn preconditions() -> ContentDigest {
    ContentDigest::sha256(b"approved pose and device generation")
}

fn next_timestamp<T: AsRef<PreparedEffect>>(effects: &EffectCoordinator, token: &T) -> TimestampNs {
    TimestampNs(
        effects
            .receipt(token)
            .expect("fixture operation is retained")
            .updated_at
            .0
            + 1,
    )
}

fn commit_effect(
    effects: &mut EffectCoordinator,
    authority: &AuthorityCx,
    tree: &RegionTree,
    leases: &mut LeaseRegistry,
    prepared: PreparedEffect,
    now: TimestampNs,
) -> Result<CommittedEffect, EffectTransitionError<PreparedEffect>> {
    let approval = CommitApproval {
        prepared_digest: prepared.digest(),
        current_precondition_digest: preconditions(),
    };
    effects.commit(authority, tree, leases, prepared, now, approval)
}

fn cancel_prepared(
    effects: &mut EffectCoordinator,
    tree: &mut RegionTree,
    authority: &AuthorityCx,
    prepared: PreparedEffect,
) -> Result<(), EffectTransitionError<PreparedEffect>> {
    let now = next_timestamp(effects, &prepared);
    effects.cancel_prepared(
        tree,
        authority,
        prepared,
        ContentDigest::sha256(b"owner cancellation"),
        now,
    )
}

fn adapter_accepted(
    effects: &mut EffectCoordinator,
    committed: &mut CommittedEffect,
) -> Result<(), EffectCoordError> {
    let now = next_timestamp(effects, committed);
    effects.adapter_accepted(committed, None, now)
}

fn observed(
    effects: &mut EffectCoordinator,
    committed: &mut CommittedEffect,
    proof: ContentDigest,
) -> Result<(), EffectCoordError> {
    let now = next_timestamp(effects, committed);
    effects.observed(committed, proof, now)
}

fn verified(
    effects: &mut EffectCoordinator,
    tree: &mut RegionTree,
    authority: &AuthorityCx,
    committed: CommittedEffect,
    proof: ContentDigest,
) -> Result<(), EffectTransitionError<CommittedEffect>> {
    let now = next_timestamp(effects, &committed);
    effects.verified(tree, authority, committed, proof, now)
}

fn failed(
    effects: &mut EffectCoordinator,
    tree: &mut RegionTree,
    authority: &AuthorityCx,
    committed: CommittedEffect,
    proof: Option<ContentDigest>,
) -> Result<(), EffectTransitionError<CommittedEffect>> {
    let now = next_timestamp(effects, &committed);
    effects.failed(
        tree,
        authority,
        committed,
        proof,
        "adapter confirmed terminal failure",
        now,
    )
}

fn indeterminate(
    effects: &mut EffectCoordinator,
    tree: &mut RegionTree,
    authority: &AuthorityCx,
    committed: CommittedEffect,
    note: Option<&str>,
) -> Result<CommittedEffect, EffectTransitionError<CommittedEffect>> {
    let now = next_timestamp(effects, &committed);
    effects.indeterminate(tree, authority, committed, note, now)
}

struct Fixture {
    effects: EffectCoordinator,
    authority: AuthorityCx,
    tree: RegionTree,
    leases: LeaseRegistry,
    fence: u64,
}

impl Fixture {
    fn new() -> Test<Self> {
        Self::with_grants(&PTZ, None)
    }

    fn with_grants(grants: &[RuntimeGrant], deadline: Option<TimestampNs>) -> Test<Self> {
        let (authority, tree) = AuthorityCx::root(
            spec("owner", grants, deadline)?,
            RegionId::new("region:owner")?,
            RegionKind::Process,
            budget()?,
            TimestampNs(1),
        )?;
        let mut leases = LeaseRegistry::default();
        let lease = leases.acquire(RESOURCE, authority.region().as_str(), None, TimestampNs(2))?;
        Ok(Self {
            effects: EffectCoordinator::new(),
            authority,
            tree,
            leases,
            fence: lease.fence,
        })
    }

    fn prepare(&mut self, name: &str) -> Test<PreparedEffect> {
        let operation = OperationId::parse(format!("operation:{name}"))?;
        Ok(self.effects.prepare(
            &self.authority,
            &mut self.tree,
            &mut self.leases,
            prepare_spec(&operation, self.fence)?,
            TimestampNs(3),
        )?)
    }

    fn child(&mut self) -> Test<AuthorityCx> {
        let child_budget = BudgetVector::builder()
            .tokens(16)
            .bytes(1024)
            .cpu_millis(100)
            .build()?;
        let mut child_spec = spec("child", &PTZ, None)?;
        child_spec.budgets = child_budget;
        Ok(self.authority.scope_down(
            &mut self.tree,
            RegionId::new("region:child")?,
            RegionKind::Property,
            child_budget,
            child_spec,
            TimestampNs(3),
        )?)
    }

    fn obligation_state(&self, obligation: &fss_core::ObligationId) -> Test<ObligationState> {
        Ok(self.tree.get(self.authority.region())?.obligations[obligation].state)
    }
}

#[test]
fn default_lease_registry_never_issues_or_accepts_the_zero_fence() -> Test {
    let mut f = Fixture::new()?;
    assert_eq!(f.fence, 1);
    assert!(matches!(
        f.leases.check_fence(RESOURCE, 0, TimestampNs(3)),
        Err(LeaseError::StaleFence {
            presented: 0,
            current: 1,
            ..
        })
    ));
    let operation = OperationId::parse("operation:zero-fence")?;
    assert!(matches!(
        f.effects.prepare(
            &f.authority,
            &mut f.tree,
            &mut f.leases,
            prepare_spec(&operation, 0)?,
            TimestampNs(3)
        ),
        Err(EffectCoordError::Fence { .. })
    ));
    assert!(f.authority.leaked_obligations(&f.tree)?.is_empty());
    Ok(())
}

#[test]
fn exact_preparation_recovers_one_record_but_cannot_reopen_a_settled_obligation() -> Test {
    let mut f = Fixture::new()?;
    let prepared = f.prepare("one-operation")?;
    let operation = prepared.operation().clone();
    let obligation = prepared.obligation().clone();
    let recovered = f.effects.prepare(
        &f.authority,
        &mut f.tree,
        &mut f.leases,
        prepare_spec(&operation, f.fence)?,
        TimestampNs(4),
    )?;
    assert_eq!(recovered.digest(), prepared.digest());
    assert_eq!(f.effects.journal().operations().count(), 1);
    assert_eq!(f.effects.journal().obligations().count(), 1);
    assert_eq!(f.tree.get(f.authority.region())?.obligations.len(), 1);
    f.authority.resolve_obligation(
        &mut f.tree,
        &obligation,
        ObligationTerminal::Drained,
        None,
        None,
    )?;
    assert!(matches!(
        f.tree.resolve_obligation(
            f.authority.region(),
            &obligation,
            ObligationState::Pending,
            None,
            None,
        ),
        Err(fss_core::RegionError::InvalidObligationTransition {
            current: ObligationState::Cancelled,
            attempted: ObligationState::Pending,
            ..
        })
    ));
    assert!(matches!(
        f.effects.prepare(
            &f.authority,
            &mut f.tree,
            &mut f.leases,
            prepare_spec(&operation, f.fence)?,
            TimestampNs(5)
        ),
        Err(EffectCoordError::Region { .. })
    ));
    assert!(matches!(
        commit_effect(
            &mut f.effects,
            &f.authority,
            &f.tree,
            &mut f.leases,
            prepared,
            TimestampNs(6)
        )
        .map_err(|refusal| refusal.into_parts().0),
        Err(EffectCoordError::Region { .. })
    ));
    assert_eq!(f.obligation_state(&obligation)?, ObligationState::Cancelled);
    assert_eq!(f.effects.state(&recovered)?, EffectState::Prepared);
    Ok(())
}

#[test]
fn operation_identity_cannot_be_prepared_again_in_another_region() -> Test {
    let mut f = Fixture::new()?;
    let child = f.child()?;
    let prepared = f.prepare("shared-operation")?;
    let resource = "device:ptz:child";
    let lease = f
        .leases
        .acquire(resource, child.region().as_str(), None, TimestampNs(4))?;
    let mut requested = prepare_spec(prepared.operation(), lease.fence)?;
    requested.resource = resource;
    assert!(matches!(
        f.effects.prepare(
            &child,
            &mut f.tree,
            &mut f.leases,
            requested,
            TimestampNs(3)
        ),
        Err(EffectCoordError::WrongAuthority { .. })
    ));
    assert!(f.tree.get(child.region())?.obligations.is_empty());
    cancel_prepared(&mut f.effects, &mut f.tree, &f.authority, prepared)?;
    Ok(())
}

#[test]
fn commit_refuses_a_child_scope_and_an_identically_named_independent_authority() -> Test {
    let mut f = Fixture::new()?;
    let child = f.child()?;
    let prepared = f.prepare("wrong-region")?;
    let obligation = prepared.obligation().clone();
    assert!(matches!(
        commit_effect(
            &mut f.effects,
            &child,
            &f.tree,
            &mut f.leases,
            prepared,
            TimestampNs(4)
        )
        .map_err(|refusal| refusal.into_parts().0),
        Err(EffectCoordError::WrongAuthority { .. })
    ));
    assert_eq!(f.obligation_state(&obligation)?, ObligationState::Pending);
    assert!(f.tree.get(child.region())?.obligations.is_empty());

    let mut original = Fixture::new()?;
    let other = Fixture::new()?;
    assert_eq!(original.authority.region(), other.authority.region());
    let prepared = original.prepare("same-names-different-owner")?;
    assert!(matches!(
        commit_effect(
            &mut original.effects,
            &other.authority,
            &original.tree,
            &mut original.leases,
            prepared,
            TimestampNs(4)
        )
        .map_err(|refusal| refusal.into_parts().0),
        Err(EffectCoordError::WrongAuthority { .. })
    ));
    Ok(())
}

#[test]
fn every_terminal_resolution_refuses_a_different_preparing_scope() -> Test {
    for transition in ["cancel", "verify", "fail", "indeterminate"] {
        let mut f = Fixture::new()?;
        let other = f.child()?;
        let prepared = f.prepare(transition)?;
        let obligation = prepared.obligation().clone();
        let result = if transition == "cancel" {
            cancel_prepared(&mut f.effects, &mut f.tree, &other, prepared)
                .map_err(|refusal| refusal.into_parts().0)
        } else {
            let mut committed = commit_effect(
                &mut f.effects,
                &f.authority,
                &f.tree,
                &mut f.leases,
                prepared,
                TimestampNs(4),
            )?;
            match transition {
                "verify" => {
                    adapter_accepted(&mut f.effects, &mut committed)?;
                    observed(
                        &mut f.effects,
                        &mut committed,
                        ContentDigest::sha256(b"observation"),
                    )?;
                    verified(
                        &mut f.effects,
                        &mut f.tree,
                        &other,
                        committed,
                        ContentDigest::sha256(b"observation"),
                    )
                    .map_err(|refusal| refusal.into_parts().0)
                }
                "fail" => failed(&mut f.effects, &mut f.tree, &other, committed, None)
                    .map_err(|refusal| refusal.into_parts().0),
                _ => indeterminate(
                    &mut f.effects,
                    &mut f.tree,
                    &other,
                    committed,
                    Some("reconcile uncertain adapter outcome"),
                )
                .map_err(|refusal| refusal.into_parts().0)
                .map(|_| ()),
            }
        };
        assert!(
            matches!(result, Err(EffectCoordError::WrongAuthority { .. })),
            "{transition}"
        );
        assert_eq!(f.obligation_state(&obligation)?, ObligationState::Pending);
        assert!(f.tree.get(other.region())?.obligations.is_empty());
    }
    Ok(())
}

#[test]
fn cancellation_and_canonical_drain_both_refuse_new_commit_authority() -> Test {
    for request_through_authority in [false, true] {
        let mut f = Fixture::new()?;
        let prepared = f.prepare("cancel-before-commit")?;
        let obligation = prepared.obligation().clone();
        if request_through_authority {
            f.authority
                .request_cancellation(&mut f.tree, TimestampNs(4))?;
        } else {
            f.tree
                .request_drain(f.authority.region(), None, TimestampNs(4))?;
        }
        let refusal = commit_effect(
            &mut f.effects,
            &f.authority,
            &f.tree,
            &mut f.leases,
            prepared,
            TimestampNs(5),
        )
        .expect_err("cancelled owner cannot commit");
        assert!(matches!(refusal.error(), EffectCoordError::Region { .. }));
        assert_eq!(f.effects.state(refusal.token())?, EffectState::Prepared);
        assert_eq!(refusal.token().obligation(), &obligation);
        assert_eq!(f.obligation_state(&obligation)?, ObligationState::Pending);
        assert!(f.prepare("after-cancel").is_err());

        // The refused commit must leave this exact preparation available for drain.
        cancel_prepared(
            &mut f.effects,
            &mut f.tree,
            &f.authority,
            refusal.into_token(),
        )?;
        assert_eq!(f.obligation_state(&obligation)?, ObligationState::Cancelled);
        assert!(f.authority.leaked_obligations(&f.tree)?.is_empty());
        f.authority.begin_drain(&mut f.tree, TimestampNs(6))?;
        assert_eq!(
            f.authority
                .finalize(&mut f.tree, TimestampNs(7))?
                .total_obligations,
            1,
        );
    }
    Ok(())
}

#[test]
fn authority_deadline_refuses_commit_at_the_exact_boundary() -> Test {
    let deadline = TimestampNs(100);
    for now in [TimestampNs(99), deadline, TimestampNs(101)] {
        let mut f = Fixture::with_grants(&PTZ, Some(deadline))?;
        let prepared = f.prepare("deadline")?;
        let obligation = prepared.obligation().clone();
        let result = commit_effect(
            &mut f.effects,
            &f.authority,
            &f.tree,
            &mut f.leases,
            prepared,
            now,
        );
        if now < deadline {
            assert_eq!(f.effects.state(&result?)?, EffectState::Committed);
        } else {
            let refusal = result.expect_err("the exact deadline must refuse");
            assert!(matches!(
                refusal.error(),
                EffectCoordError::Deadline { deadline: found, now: attempted, .. }
                    if *found == deadline && *attempted == now
            ));
            assert_eq!(f.effects.state(refusal.token())?, EffectState::Prepared);
            cancel_prepared(
                &mut f.effects,
                &mut f.tree,
                &f.authority,
                refusal.into_token(),
            )?;
            assert_eq!(f.obligation_state(&obligation)?, ObligationState::Cancelled);
        }
    }
    Ok(())
}

#[test]
fn effect_preparation_and_commit_enforce_resource_scopes() -> Test {
    let elsewhere = BTreeSet::from(["device:ptz:elsewhere".to_owned()]);
    let mut f = Fixture::new()?;
    f.authority.narrow_grants(
        f.authority
            .grants()
            .clone()
            .with_scope(PTZ[0], elsewhere.clone()),
    )?;
    let operation = OperationId::parse("operation:outside-prepare-scope")?;
    assert!(matches!(
        f.effects.prepare(
            &f.authority,
            &mut f.tree,
            &mut f.leases,
            prepare_spec(&operation, f.fence)?,
            TimestampNs(3)
        ),
        Err(EffectCoordError::Grant {
            error: GrantError::OutsideScope { .. },
            ..
        })
    ));
    assert!(f.authority.leaked_obligations(&f.tree)?.is_empty());

    let mut f = Fixture::new()?;
    let prepared = f.prepare("outside-commit-scope")?;
    f.authority
        .narrow_grants(f.authority.grants().clone().with_scope(PTZ[1], elsewhere))?;
    assert!(matches!(
        commit_effect(
            &mut f.effects,
            &f.authority,
            &f.tree,
            &mut f.leases,
            prepared,
            TimestampNs(4)
        )
        .map_err(|refusal| refusal.into_parts().0),
        Err(EffectCoordError::Grant {
            error: GrantError::OutsideScope { .. },
            ..
        })
    ));

    let mut f = Fixture::new()?;
    let allowed = BTreeSet::from([RESOURCE.to_owned()]);
    f.authority.narrow_grants(
        f.authority
            .grants()
            .clone()
            .with_scope(PTZ[0], allowed.clone())
            .with_scope(PTZ[1], allowed),
    )?;
    let prepared = f.prepare("inside-resource-scope")?;
    assert_eq!(
        commit_effect(
            &mut f.effects,
            &f.authority,
            &f.tree,
            &mut f.leases,
            prepared,
            TimestampNs(4)
        )?
        .resource(),
        RESOURCE,
    );
    Ok(())
}

#[test]
fn mismatched_and_nondomain_grants_cannot_authorize_an_effect() -> Test {
    for (prepare, commit) in [
        (RuntimeGrant::PtzPrepare, RuntimeGrant::AlertCommit),
        (RuntimeGrant::PtzCommit, RuntimeGrant::PtzPrepare),
        (RuntimeGrant::ReadMedia, RuntimeGrant::ReadMedia),
        (
            RuntimeGrant::AgentPlanPrepare,
            RuntimeGrant::AgentPlanCommit,
        ),
        (
            RuntimeGrant::EventReviewPrepare,
            RuntimeGrant::EventReviewCommit,
        ),
    ] {
        let grants: Vec<_> = BTreeSet::from([prepare, commit]).into_iter().collect();
        let mut f = Fixture::with_grants(&grants, None)?;
        let operation = OperationId::parse("operation:bad-grant-pair")?;
        let mut requested = prepare_spec(&operation, f.fence)?;
        requested.prepare_grant = prepare;
        requested.commit_grant = commit;
        assert!(matches!(
            f.effects.prepare(
                &f.authority,
                &mut f.tree,
                &mut f.leases,
                requested,
                TimestampNs(3)
            ),
            Err(EffectCoordError::InvalidGrantPair { .. })
        ));
        assert!(f.authority.leaked_obligations(&f.tree)?.is_empty());
    }
    Ok(())
}

#[test]
fn all_registered_domain_effect_pairs_can_prepare_and_commit() -> Test {
    for (prepare, commit) in [
        (RuntimeGrant::AlertPrepare, RuntimeGrant::AlertCommit),
        (RuntimeGrant::PtzPrepare, RuntimeGrant::PtzCommit),
        (
            RuntimeGrant::RetentionPrepare,
            RuntimeGrant::RetentionCommit,
        ),
        (RuntimeGrant::ExportPrepare, RuntimeGrant::ExportCommit),
        (RuntimeGrant::DeletePrepare, RuntimeGrant::DeleteCommit),
        (RuntimeGrant::RepairPrepare, RuntimeGrant::RepairCommit),
    ] {
        let mut f = Fixture::with_grants(&[prepare, commit], None)?;
        let operation = OperationId::parse("operation:domain-pair")?;
        let mut requested = prepare_spec(&operation, f.fence)?;
        requested.prepare_grant = prepare;
        requested.commit_grant = commit;
        let prepared = f.effects.prepare(
            &f.authority,
            &mut f.tree,
            &mut f.leases,
            requested,
            TimestampNs(3),
        )?;
        assert_eq!(prepared.resource(), RESOURCE);
        assert_eq!(prepared.fence(), f.fence);
        let committed = commit_effect(
            &mut f.effects,
            &f.authority,
            &f.tree,
            &mut f.leases,
            prepared,
            TimestampNs(4),
        )?;
        assert_eq!(f.effects.state(&committed)?, EffectState::Committed);
        assert_eq!(committed.fence(), f.fence);
    }
    Ok(())
}

#[test]
fn preparation_and_commit_refuse_another_regions_current_lease() -> Test {
    let mut f = Fixture::new()?;
    let mut foreign = LeaseRegistry::new();
    let lease = foreign.acquire(RESOURCE, "region:other", None, TimestampNs(2))?;
    assert_eq!(lease.fence, f.fence);
    let operation = OperationId::parse("operation:foreign-holder")?;
    assert!(matches!(
        f.effects.prepare(
            &f.authority,
            &mut f.tree,
            &mut foreign,
            prepare_spec(&operation, lease.fence)?,
            TimestampNs(3)
        ),
        Err(EffectCoordError::LeaseHolder { .. })
    ));
    assert!(f.authority.leaked_obligations(&f.tree)?.is_empty());
    let prepared = f.prepare("holder-changed")?;
    assert!(matches!(
        commit_effect(
            &mut f.effects,
            &f.authority,
            &f.tree,
            &mut foreign,
            prepared,
            TimestampNs(4)
        )
        .map_err(|refusal| refusal.into_parts().0),
        Err(EffectCoordError::WrongLeaseRegistry { .. })
    ));
    Ok(())
}

#[test]
fn replacement_registry_cannot_redeem_the_same_holder_and_numeric_fence() -> Test {
    for revoke_original in [false, true] {
        for use_default in [false, true] {
            let mut f = Fixture::new()?;
            let prepared = f.prepare("replacement-registry")?;
            let obligation = prepared.obligation().clone();
            if revoke_original {
                f.leases.revoke(&format!("lease:{RESOURCE}:{}", f.fence))?;
            }
            let mut replacement = if use_default {
                LeaseRegistry::default()
            } else {
                LeaseRegistry::new()
            };
            let replacement_lease = replacement.acquire(
                RESOURCE,
                f.authority.region().as_str(),
                None,
                TimestampNs(3),
            )?;
            assert_eq!(replacement_lease.fence, f.fence);
            replacement.check_fence(RESOURCE, f.fence, TimestampNs(4))?;
            assert!(matches!(
                commit_effect(
                    &mut f.effects,
                    &f.authority,
                    &f.tree,
                    &mut replacement,
                    prepared,
                    TimestampNs(4)
                )
                .map_err(|refusal| refusal.into_parts().0),
                Err(EffectCoordError::WrongLeaseRegistry { .. })
            ));
            assert_eq!(f.obligation_state(&obligation)?, ObligationState::Pending);
            assert_eq!(
                replacement.get(&replacement_lease.id),
                Some(&replacement_lease)
            );
        }
    }
    Ok(())
}

#[test]
fn moving_the_issuing_registry_preserves_the_prepared_fence_authority() -> Test {
    let mut f = Fixture::new()?;
    let prepared = f.prepare("move-registry")?;
    let mut moved = std::mem::take(&mut f.leases);
    let committed = commit_effect(
        &mut f.effects,
        &f.authority,
        &f.tree,
        &mut moved,
        prepared,
        TimestampNs(4),
    )?;
    assert_eq!(f.effects.state(&committed)?, EffectState::Committed);
    assert_eq!(committed.fence(), f.fence);
    assert_eq!(f.leases.current_fence(RESOURCE), None);
    Ok(())
}

#[test]
fn a_stale_tree_snapshot_cannot_hide_drain_from_preparation_or_commit() -> Test {
    let mut f = Fixture::new()?;
    let mut stale = f.tree.clone();
    f.tree
        .request_drain(f.authority.region(), None, TimestampNs(3))?;
    let operation = OperationId::parse("operation:prepare-stale-tree")?;
    assert!(matches!(
        f.effects.prepare(
            &f.authority,
            &mut stale,
            &mut f.leases,
            prepare_spec(&operation, f.fence)?,
            TimestampNs(3)
        ),
        Err(EffectCoordError::Region { .. })
    ));
    assert!(f.tree.get(f.authority.region())?.obligations.is_empty());
    assert!(stale.get(f.authority.region())?.obligations.is_empty());

    let mut f = Fixture::new()?;
    let prepared = f.prepare("commit-stale-tree")?;
    let obligation = prepared.obligation().clone();
    let stale = f.tree.clone();
    f.tree
        .request_drain(f.authority.region(), None, TimestampNs(3))?;
    assert!(matches!(
        commit_effect(
            &mut f.effects,
            &f.authority,
            &stale,
            &mut f.leases,
            prepared,
            TimestampNs(4)
        )
        .map_err(|refusal| refusal.into_parts().0),
        Err(EffectCoordError::Region { .. })
    ));
    assert_eq!(f.obligation_state(&obligation)?, ObligationState::Pending);
    Ok(())
}

#[test]
fn terminal_effect_transitions_cannot_settle_a_cloned_tree_snapshot() -> Test {
    for transition in ["cancel", "verify", "fail", "indeterminate"] {
        let mut f = Fixture::new()?;
        let prepared = f.prepare(transition)?;
        let obligation = prepared.obligation().clone();
        let mut stale = f.tree.clone();
        let result = if transition == "cancel" {
            cancel_prepared(&mut f.effects, &mut stale, &f.authority, prepared)
                .map_err(|refusal| refusal.into_parts().0)
        } else {
            let mut committed = commit_effect(
                &mut f.effects,
                &f.authority,
                &f.tree,
                &mut f.leases,
                prepared,
                TimestampNs(4),
            )?;
            match transition {
                "verify" => {
                    adapter_accepted(&mut f.effects, &mut committed)?;
                    observed(
                        &mut f.effects,
                        &mut committed,
                        ContentDigest::sha256(b"observation"),
                    )?;
                    verified(
                        &mut f.effects,
                        &mut stale,
                        &f.authority,
                        committed,
                        ContentDigest::sha256(b"observation"),
                    )
                    .map_err(|refusal| refusal.into_parts().0)
                }
                "fail" => failed(&mut f.effects, &mut stale, &f.authority, committed, None)
                    .map_err(|refusal| refusal.into_parts().0),
                _ => indeterminate(
                    &mut f.effects,
                    &mut stale,
                    &f.authority,
                    committed,
                    Some("reconcile uncertain adapter outcome"),
                )
                .map_err(|refusal| refusal.into_parts().0)
                .map(|_| ()),
            }
        };
        assert!(
            matches!(result, Err(EffectCoordError::Region { .. })),
            "{transition}"
        );
        assert_eq!(f.obligation_state(&obligation)?, ObligationState::Pending);
        assert_eq!(
            stale.get(f.authority.region())?.obligations[&obligation].state,
            ObligationState::Pending
        );
        assert!(
            stale
                .get(f.authority.region())?
                .reconciliation_obligations
                .is_empty()
        );
    }
    Ok(())
}

#[test]
fn commit_revalidates_revocation_release_and_exact_lease_expiry() -> Test {
    for change in ["revoke", "release", "expire"] {
        let mut f = Fixture::new()?;
        let prepared = f.prepare(change)?;
        let obligation = prepared.obligation().clone();
        let lease_id = format!("lease:{RESOURCE}:{}", f.fence);
        match change {
            "revoke" => f.leases.revoke(&lease_id)?,
            "release" => f.leases.release(&lease_id)?,
            _ => f.leases.renew(&lease_id, 8, TimestampNs(2))?,
        }
        assert!(
            matches!(
                commit_effect(
                    &mut f.effects,
                    &f.authority,
                    &f.tree,
                    &mut f.leases,
                    prepared,
                    TimestampNs(10)
                )
                .map_err(|refusal| refusal.into_parts().0),
                Err(EffectCoordError::Fence { .. })
            ),
            "{change}"
        );
        assert_eq!(f.obligation_state(&obligation)?, ObligationState::Pending);
    }
    Ok(())
}

#[test]
fn observed_expiry_cannot_be_reversed_through_another_lease_access_path() -> Test {
    for expiry_path in ["check", "renew"] {
        let mut f = Fixture::new()?;
        let lease_id = format!("lease:{RESOURCE}:{}", f.fence);
        f.leases.renew(&lease_id, 8, TimestampNs(2))?;
        match expiry_path {
            "check" => assert!(matches!(
                f.leases.check_fence(RESOURCE, f.fence, TimestampNs(10)),
                Err(LeaseError::LeaseExpired { .. })
            )),
            _ => assert!(matches!(
                f.leases.renew(&lease_id, 20, TimestampNs(10)),
                Err(LeaseError::NotActive {
                    state: LeaseState::Expired,
                    ..
                })
            )),
        }
        assert_eq!(
            f.leases.get(&lease_id).map(|lease| lease.state),
            Some(LeaseState::Expired)
        );
        assert!(matches!(
            f.leases.check_fence(RESOURCE, f.fence, TimestampNs(9)),
            Err(LeaseError::LeaseExpired { .. })
        ));
        assert!(matches!(
            f.leases.renew(&lease_id, 20, TimestampNs(9)),
            Err(LeaseError::NotActive {
                state: LeaseState::Expired,
                ..
            })
        ));
        assert!(f.prepare("expired-lease-preparation").is_err());
        assert!(f.authority.leaked_obligations(&f.tree)?.is_empty());
        let takeover = f.leases.acquire(
            RESOURCE,
            f.authority.region().as_str(),
            None,
            TimestampNs(11),
        )?;
        assert!(takeover.fence > f.fence);
        f.leases
            .check_fence(RESOURCE, takeover.fence, TimestampNs(12))?;
        assert!(matches!(
            f.leases.check_fence(RESOURCE, f.fence, TimestampNs(12)),
            Err(LeaseError::StaleFence { .. })
        ));
    }
    Ok(())
}

#[test]
fn indeterminate_reconciliation_retains_the_unique_token_for_a_late_observation() -> Test {
    let mut f = Fixture::new()?;
    let prepared = f.prepare("late-observation")?;
    let obligation = prepared.obligation().clone();
    let committed = commit_effect(
        &mut f.effects,
        &f.authority,
        &f.tree,
        &mut f.leases,
        prepared,
        TimestampNs(4),
    )?;
    f.authority
        .request_cancellation(&mut f.tree, TimestampNs(5))?;
    let note = "query the adapter for the uncertain pose change";
    let mut committed = indeterminate(
        &mut f.effects,
        &mut f.tree,
        &f.authority,
        committed,
        Some(note),
    )?;
    assert_eq!(f.effects.state(&committed)?, EffectState::Indeterminate);
    assert_eq!(
        f.obligation_state(&obligation)?,
        ObligationState::Indeterminate
    );
    assert_eq!(
        f.tree.get(f.authority.region())?.reconciliation_obligations[&obligation],
        note
    );
    let proof = ContentDigest::sha256(b"late native adapter observation");
    observed(&mut f.effects, &mut committed, proof)?;
    verified(&mut f.effects, &mut f.tree, &f.authority, committed, proof)?;
    assert_eq!(f.obligation_state(&obligation)?, ObligationState::Verified);
    assert_eq!(
        f.tree.get(f.authority.region())?.obligations[&obligation].proof_digest,
        Some(proof)
    );
    assert!(
        f.tree
            .get(f.authority.region())?
            .reconciliation_obligations
            .is_empty()
    );
    Ok(())
}

#[test]
fn late_failure_reconciliation_requires_evidence_and_clears_the_active_note() -> Test {
    let mut f = Fixture::new()?;
    let prepared = f.prepare("late-failure")?;
    let obligation = prepared.obligation().clone();
    let committed = commit_effect(
        &mut f.effects,
        &f.authority,
        &f.tree,
        &mut f.leases,
        prepared,
        TimestampNs(4),
    )?;
    let note = "query the adapter for evidence resolving the uncertain pose change";
    let committed = indeterminate(
        &mut f.effects,
        &mut f.tree,
        &f.authority,
        committed,
        Some(note),
    )?;
    f.authority
        .request_cancellation(&mut f.tree, TimestampNs(5))?;

    let refusal = failed(&mut f.effects, &mut f.tree, &f.authority, committed, None)
        .expect_err("uncertainty cannot become failure without evidence");
    assert!(matches!(
        refusal.error(),
        EffectCoordError::Journal {
            error: fss_core::ContractError::EvidenceRequired,
            ..
        }
    ));
    assert_eq!(
        f.effects.state(refusal.token())?,
        EffectState::Indeterminate
    );
    let node = f.tree.get(f.authority.region())?;
    assert_eq!(
        node.obligations[&obligation].state,
        ObligationState::Indeterminate
    );
    assert_eq!(node.obligations[&obligation].proof_digest, None);
    assert_eq!(node.reconciliation_obligations[&obligation], note);

    // Evidence arrives later; recover this same effect instead of preparing a new one.
    let proof = ContentDigest::sha256(b"adapter proved pose change failed");
    failed(
        &mut f.effects,
        &mut f.tree,
        &f.authority,
        refusal.into_token(),
        Some(proof),
    )?;
    let node = f.tree.get(f.authority.region())?;
    assert_eq!(node.obligations.len(), 1);
    assert_eq!(node.obligations[&obligation].state, ObligationState::Failed);
    assert_eq!(node.obligations[&obligation].proof_digest, Some(proof));
    assert!(node.reconciliation_obligations.is_empty());
    f.authority.begin_drain(&mut f.tree, TimestampNs(6))?;
    let proof = f.authority.finalize(&mut f.tree, TimestampNs(7))?;
    assert_eq!(proof.indeterminate_obligations, 0);
    assert_eq!(proof.total_obligations, 1);
    Ok(())
}

#[test]
fn absent_or_blank_reconciliation_notes_never_settle_an_uncertain_effect() -> Test {
    for note in [None, Some(""), Some(" \n ")] {
        let mut f = Fixture::new()?;
        let prepared = f.prepare("missing-note")?;
        let obligation = prepared.obligation().clone();
        let committed = commit_effect(
            &mut f.effects,
            &f.authority,
            &f.tree,
            &mut f.leases,
            prepared,
            TimestampNs(4),
        )?;
        let refusal = indeterminate(&mut f.effects, &mut f.tree, &f.authority, committed, note)
            .expect_err("a reconciliation note is required");
        assert!(matches!(
            refusal.error(),
            EffectCoordError::IndeterminateWithoutNote { .. }
        ));
        assert_eq!(f.effects.state(refusal.token())?, EffectState::Committed);
        assert_eq!(f.obligation_state(&obligation)?, ObligationState::Pending);
        assert!(
            f.tree
                .get(f.authority.region())?
                .reconciliation_obligations
                .is_empty()
        );

        let mut recovered = indeterminate(
            &mut f.effects,
            &mut f.tree,
            &f.authority,
            refusal.into_token(),
            Some("query the adapter for the original operation"),
        )?;
        assert_eq!(f.effects.state(&recovered)?, EffectState::Indeterminate);
        observed(
            &mut f.effects,
            &mut recovered,
            ContentDigest::sha256(b"late adapter observation"),
        )?;
        verified(
            &mut f.effects,
            &mut f.tree,
            &f.authority,
            recovered,
            ContentDigest::sha256(b"late adapter observation"),
        )?;
        assert_eq!(f.obligation_state(&obligation)?, ObligationState::Verified);
    }
    Ok(())
}

#[test]
fn refused_commit_recovers_the_same_preparation_across_owner_tree_and_registry_errors() -> Test {
    let mut f = Fixture::new()?;
    let other = Fixture::new()?;
    let prepared = f.prepare("recover-commit")?;
    let operation = prepared.operation().clone();
    let obligation = prepared.obligation().clone();
    let before = f.tree.get(f.authority.region())?.obligations.clone();

    let refusal = commit_effect(
        &mut f.effects,
        &other.authority,
        &f.tree,
        &mut f.leases,
        prepared,
        TimestampNs(4),
    )
    .expect_err("a matching region label does not grant authority");
    assert!(matches!(
        refusal.error(),
        EffectCoordError::WrongAuthority { .. }
    ));
    assert_eq!(refusal.token().operation(), &operation);
    assert_eq!(f.effects.state(refusal.token())?, EffectState::Prepared);
    assert_eq!(refusal.to_string(), refusal.error().to_string());
    assert!(refusal.source().is_some());
    let (_, prepared) = refusal.into_parts();

    let snapshot = f.tree.clone();
    let refusal = commit_effect(
        &mut f.effects,
        &f.authority,
        &snapshot,
        &mut f.leases,
        prepared,
        TimestampNs(4),
    )
    .expect_err("a cloned tree cannot authorize commit");
    assert!(matches!(refusal.error(), EffectCoordError::Region { .. }));
    assert_eq!(refusal.token().obligation(), &obligation);
    let prepared = refusal.into_token();

    let mut replacement = LeaseRegistry::new();
    let replacement_lease = replacement.acquire(
        RESOURCE,
        f.authority.region().as_str(),
        None,
        TimestampNs(2),
    )?;
    assert_eq!(replacement_lease.fence, f.fence);
    let refusal = commit_effect(
        &mut f.effects,
        &f.authority,
        &f.tree,
        &mut replacement,
        prepared,
        TimestampNs(4),
    )
    .expect_err("the original issuing registry is required");
    assert!(matches!(
        refusal.error(),
        EffectCoordError::WrongLeaseRegistry { .. }
    ));
    assert_eq!(refusal.token().resource(), RESOURCE);
    assert_eq!(refusal.token().fence(), f.fence);
    assert_eq!(refusal.token().terminal_predicate(), PREDICATE);
    assert_eq!(f.effects.state(refusal.token())?, EffectState::Prepared);
    assert_eq!(f.tree.get(f.authority.region())?.obligations, before);

    let mut committed = commit_effect(
        &mut f.effects,
        &f.authority,
        &f.tree,
        &mut f.leases,
        refusal.into_token(),
        TimestampNs(4),
    )?;
    assert_eq!(committed.operation(), &operation);
    adapter_accepted(&mut f.effects, &mut committed)?;
    observed(
        &mut f.effects,
        &mut committed,
        ContentDigest::sha256(b"original operation's observed pose"),
    )?;
    verified(
        &mut f.effects,
        &mut f.tree,
        &f.authority,
        committed,
        ContentDigest::sha256(b"original operation's observed pose"),
    )?;
    assert_eq!(f.obligation_state(&obligation)?, ObligationState::Verified);
    assert_eq!(f.tree.get(f.authority.region())?.obligations.len(), 1);
    Ok(())
}

#[test]
fn refused_cancel_returns_the_original_preparation_for_its_owner_to_drain() -> Test {
    let mut f = Fixture::new()?;
    let other = Fixture::new()?;
    let prepared = f.prepare("recover-cancel")?;
    let obligation = prepared.obligation().clone();
    let refusal = cancel_prepared(&mut f.effects, &mut f.tree, &other.authority, prepared)
        .expect_err("another owner cannot cancel the preparation");
    assert!(matches!(
        refusal.error(),
        EffectCoordError::WrongAuthority { .. }
    ));
    assert_eq!(f.effects.state(refusal.token())?, EffectState::Prepared);

    let mut snapshot = f.tree.clone();
    let refusal = cancel_prepared(
        &mut f.effects,
        &mut snapshot,
        &f.authority,
        refusal.into_token(),
    )
    .expect_err("a snapshot cannot settle the obligation");
    assert!(matches!(refusal.error(), EffectCoordError::Region { .. }));
    assert_eq!(f.effects.state(refusal.token())?, EffectState::Prepared);
    assert_eq!(f.obligation_state(&obligation)?, ObligationState::Pending);
    assert_eq!(
        snapshot.get(f.authority.region())?.obligations[&obligation].state,
        ObligationState::Pending,
    );

    f.authority
        .request_cancellation(&mut f.tree, TimestampNs(5))?;
    cancel_prepared(
        &mut f.effects,
        &mut f.tree,
        &f.authority,
        refusal.into_token(),
    )?;
    assert_eq!(f.obligation_state(&obligation)?, ObligationState::Cancelled);
    f.authority.begin_drain(&mut f.tree, TimestampNs(6))?;
    assert_eq!(
        f.authority
            .finalize(&mut f.tree, TimestampNs(7))?
            .total_obligations,
        1,
    );
    Ok(())
}

#[test]
fn refused_verification_preserves_progress_until_observed_under_the_right_owner() -> Test {
    let mut f = Fixture::new()?;
    let other = Fixture::new()?;
    let prepared = f.prepare("recover-verify")?;
    let obligation = prepared.obligation().clone();
    let committed = commit_effect(
        &mut f.effects,
        &f.authority,
        &f.tree,
        &mut f.leases,
        prepared,
        TimestampNs(4),
    )?;
    let proof = ContentDigest::sha256(b"verified after adapter observation");
    let refusal = verified(&mut f.effects, &mut f.tree, &f.authority, committed, proof)
        .expect_err("commit alone is not observation");
    assert!(matches!(
        refusal.error(),
        EffectCoordError::IllegalTransition {
            from: EffectState::Committed,
            to: EffectState::Verified,
            ..
        },
    ));
    assert_eq!(f.effects.state(refusal.token())?, EffectState::Committed);
    let mut committed = refusal.into_token();
    adapter_accepted(&mut f.effects, &mut committed)?;
    observed(&mut f.effects, &mut committed, proof)?;

    let refusal = verified(
        &mut f.effects,
        &mut f.tree,
        &other.authority,
        committed,
        proof,
    )
    .expect_err("a different owner cannot resolve the original obligation");
    assert!(matches!(
        refusal.error(),
        EffectCoordError::WrongAuthority { .. }
    ));
    assert_eq!(f.effects.state(refusal.token())?, EffectState::Observed);
    let mut snapshot = f.tree.clone();
    let refusal = verified(
        &mut f.effects,
        &mut snapshot,
        &f.authority,
        refusal.into_token(),
        proof,
    )
    .expect_err("a snapshot cannot accept the proof");
    assert!(matches!(refusal.error(), EffectCoordError::Region { .. }));
    assert_eq!(f.effects.state(refusal.token())?, EffectState::Observed);
    assert_eq!(f.obligation_state(&obligation)?, ObligationState::Pending);

    verified(
        &mut f.effects,
        &mut f.tree,
        &f.authority,
        refusal.into_token(),
        proof,
    )?;
    assert_eq!(f.obligation_state(&obligation)?, ObligationState::Verified);
    assert_eq!(
        f.tree.get(f.authority.region())?.obligations[&obligation].proof_digest,
        Some(proof),
    );
    Ok(())
}

#[test]
fn refused_failure_preserves_an_observed_effect_for_verification() -> Test {
    let mut f = Fixture::new()?;
    let prepared = f.prepare("recover-failure")?;
    let obligation = prepared.obligation().clone();
    let mut committed = commit_effect(
        &mut f.effects,
        &f.authority,
        &f.tree,
        &mut f.leases,
        prepared,
        TimestampNs(4),
    )?;
    adapter_accepted(&mut f.effects, &mut committed)?;
    observed(
        &mut f.effects,
        &mut committed,
        ContentDigest::sha256(b"unchanged observation proved success"),
    )?;
    let refusal = failed(
        &mut f.effects,
        &mut f.tree,
        &f.authority,
        committed,
        Some(ContentDigest::sha256(b"reported failure after observation")),
    )
    .expect_err("an observation cannot be silently relabeled failure");
    assert!(matches!(
        refusal.error(),
        EffectCoordError::IllegalTransition {
            from: EffectState::Observed,
            to: EffectState::Failed,
            ..
        },
    ));
    assert_eq!(f.effects.state(refusal.token())?, EffectState::Observed);
    assert_eq!(f.obligation_state(&obligation)?, ObligationState::Pending);
    verified(
        &mut f.effects,
        &mut f.tree,
        &f.authority,
        refusal.into_token(),
        ContentDigest::sha256(b"unchanged observation proved success"),
    )?;
    assert_eq!(f.obligation_state(&obligation)?, ObligationState::Verified);
    Ok(())
}

#[test]
fn conflicting_reconciliation_note_returns_the_unchanged_observed_token() -> Test {
    let mut f = Fixture::new()?;
    let prepared = f.prepare("recover-reconciliation-note")?;
    let obligation = prepared.obligation().clone();
    let committed = commit_effect(
        &mut f.effects,
        &f.authority,
        &f.tree,
        &mut f.leases,
        prepared,
        TimestampNs(4),
    )?;
    let note = "query the original adapter receipt";
    let mut committed = indeterminate(
        &mut f.effects,
        &mut f.tree,
        &f.authority,
        committed,
        Some(note),
    )?;
    observed(
        &mut f.effects,
        &mut committed,
        ContentDigest::sha256(b"observed pose"),
    )?;
    let before = f.tree.get(f.authority.region())?.obligations.clone();

    let refusal = indeterminate(
        &mut f.effects,
        &mut f.tree,
        &f.authority,
        committed,
        Some("replace the original reconciliation record"),
    )
    .expect_err("a conflicting note must preserve the existing record");
    assert!(matches!(refusal.error(), EffectCoordError::Region { .. }));
    assert_eq!(f.effects.state(refusal.token())?, EffectState::Observed);
    assert_eq!(f.tree.get(f.authority.region())?.obligations, before);
    assert_eq!(
        f.tree.get(f.authority.region())?.reconciliation_obligations[&obligation],
        note,
    );

    let committed = indeterminate(
        &mut f.effects,
        &mut f.tree,
        &f.authority,
        refusal.into_token(),
        Some(note),
    )?;
    assert_eq!(f.effects.state(&committed)?, EffectState::Indeterminate);
    failed(
        &mut f.effects,
        &mut f.tree,
        &f.authority,
        committed,
        Some(ContentDigest::sha256(b"adapter confirmed terminal failure")),
    )?;
    assert_eq!(f.obligation_state(&obligation)?, ObligationState::Failed);
    assert!(
        f.tree
            .get(f.authority.region())?
            .reconciliation_obligations
            .is_empty()
    );
    Ok(())
}

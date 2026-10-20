#![forbid(unsafe_code)]
//! Canonical effect state survives caller-handle loss and retains exact proof bindings.

use std::error::Error;

use fss_core::{
    BudgetVector, ContentDigest, ContractError, EffectState, IdempotencyKey, ObligationState,
    OperationId, RegionId, RegionKind, RegionTree, RootAuthoritySpec, RuntimeGrant, TimestampNs,
};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::effect::{
    CommitApproval, CommittedEffect, EffectCoordError, EffectCoordinator, PrepareSpec,
    PreparedEffect, Reconciliation,
};
use fss_runtime::lease::LeaseRegistry;

type Test<T = ()> = Result<T, Box<dyn Error>>;
const RESOURCE: &str = "device:ptz:proof-fixture";
const PREDICATE: &str = "camera reached the requested pose";

fn digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::sha256(bytes)
}

fn preconditions() -> ContentDigest {
    digest(b"camera generation 7 and approved pose")
}

fn request<'a>(operation: &'a OperationId, fence: u64) -> Test<PrepareSpec<'a>> {
    Ok(PrepareSpec {
        operation,
        idempotency_key: IdempotencyKey::parse(operation.as_str())?,
        request_digest: digest(operation.as_str().as_bytes()),
        precondition_digest: preconditions(),
        resource: RESOURCE,
        fence,
        prepare_grant: RuntimeGrant::PtzPrepare,
        commit_grant: RuntimeGrant::PtzCommit,
        terminal_predicate: PREDICATE,
    })
}

fn approval(prepared: &PreparedEffect) -> CommitApproval {
    CommitApproval {
        prepared_digest: prepared.digest(),
        current_precondition_digest: preconditions(),
    }
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
        let budgets = BudgetVector::builder()
            .tokens(128)
            .bytes(8192)
            .cpu_millis(1000)
            .build()?;
        let (authority, tree) = AuthorityCx::root(
            RootAuthoritySpec {
                trace_id: "trace:proof-contract".into(),
                operation_id: OperationId::parse("operation:proof-scope")?,
                principal: "principal:owner".into(),
                capabilities: [
                    RuntimeGrant::PtzPrepare,
                    RuntimeGrant::PtzCommit,
                    RuntimeGrant::AlertPrepare,
                    RuntimeGrant::AlertCommit,
                ]
                .into_iter()
                .map(|grant| grant.as_str().to_owned())
                .collect(),
                deadline: None,
                priority: 10,
                budgets,
                privacy_scope: "privacy:local".into(),
                retention_scope: "retention:approved".into(),
                anchor_universe: digest(b"proof fixture anchor"),
                generation: 1,
            },
            RegionId::new("region:proof-owner")?,
            RegionKind::Process,
            budgets,
            TimestampNs(1),
        )?;
        let mut leases = LeaseRegistry::new();
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
            request(&operation, self.fence)?,
            TimestampNs(3),
        )?)
    }

    fn commit(&mut self, prepared: PreparedEffect) -> Test<CommittedEffect> {
        let approved = approval(&prepared);
        Ok(self.effects.commit(
            &self.authority,
            &self.tree,
            &mut self.leases,
            prepared,
            TimestampNs(4),
            approved,
        )?)
    }
}

#[test]
fn commit_requires_exact_preparation_and_current_preconditions_without_losing_the_token() -> Test {
    let mut f = Fixture::new()?;
    let prepared = f.prepare("approval")?;
    let before = f.effects.journal().clone();
    let obligations = f.tree.get(f.authority.region())?.obligations.clone();
    let refusal = f
        .effects
        .commit(
            &f.authority,
            &f.tree,
            &mut f.leases,
            prepared,
            TimestampNs(4),
            CommitApproval {
                prepared_digest: digest(b"another prepared action"),
                current_precondition_digest: preconditions(),
            },
        )
        .expect_err("an unrelated preparation digest cannot authorize this action");
    assert!(matches!(
        refusal.error(),
        EffectCoordError::ApprovalMismatch { .. }
    ));
    assert_eq!(f.effects.journal(), &before);
    assert_eq!(f.tree.get(f.authority.region())?.obligations, obligations);
    let prepared = refusal.into_token();
    let approved = CommitApproval {
        prepared_digest: prepared.digest(),
        current_precondition_digest: digest(b"changed generation"),
    };
    let refusal = f
        .effects
        .commit(
            &f.authority,
            &f.tree,
            &mut f.leases,
            prepared,
            TimestampNs(4),
            approved,
        )
        .expect_err("stale preconditions must refuse before dispatch");
    assert!(matches!(
        refusal.error(),
        EffectCoordError::PreconditionMismatch { .. }
    ));
    assert_eq!(f.effects.journal(), &before);
    let committed = f.commit(refusal.into_token())?;
    assert_eq!(f.effects.state(&committed)?, EffectState::Committed);
    assert_eq!(f.effects.journal().operations().count(), 1);
    Ok(())
}

#[test]
fn preparation_binds_every_request_field_and_idempotency_cannot_alias_another_operation() -> Test {
    let mut f = Fixture::new()?;
    let prepared = f.prepare("binding")?;
    let operation = prepared.operation().clone();
    let before = f.effects.journal().clone();
    for changed in [
        "request",
        "preconditions",
        "resource",
        "fence",
        "grants",
        "predicate",
        "idempotency",
    ] {
        let mut spec = request(&operation, f.fence)?;
        match changed {
            "request" => spec.request_digest = digest(b"different request"),
            "preconditions" => spec.precondition_digest = digest(b"different preconditions"),
            "resource" => spec.resource = "device:ptz:other",
            "fence" => spec.fence += 1,
            "grants" => {
                spec.prepare_grant = RuntimeGrant::AlertPrepare;
                spec.commit_grant = RuntimeGrant::AlertCommit;
            }
            "predicate" => spec.terminal_predicate = "different postcondition",
            _ => spec.idempotency_key = IdempotencyKey::parse("idempotency:different")?,
        }
        assert!(
            f.effects
                .prepare(
                    &f.authority,
                    &mut f.tree,
                    &mut f.leases,
                    spec,
                    TimestampNs(5)
                )
                .is_err(),
            "{changed}"
        );
        assert_eq!(f.effects.journal(), &before, "{changed}");
        assert_eq!(
            f.tree.get(f.authority.region())?.obligations.len(),
            1,
            "{changed}"
        );
    }
    let another = OperationId::parse("operation:alias")?;
    let mut alias = request(&another, f.fence)?;
    alias.idempotency_key = IdempotencyKey::parse(operation.as_str())?;
    assert!(matches!(
        f.effects.prepare(
            &f.authority,
            &mut f.tree,
            &mut f.leases,
            alias,
            TimestampNs(5)
        ),
        Err(EffectCoordError::Journal {
            error: ContractError::IdempotencyConflict,
            ..
        })
    ));
    assert_eq!(f.effects.journal(), &before);
    let same = f.effects.prepare(
        &f.authority,
        &mut f.tree,
        &mut f.leases,
        request(&operation, f.fence)?,
        TimestampNs(100),
    )?;
    assert_eq!(same.digest(), prepared.digest());
    assert_eq!(f.effects.receipt(&same)?.prepared_at, TimestampNs(3));
    assert_eq!(f.effects.journal(), &before);
    Ok(())
}

#[test]
fn losing_handles_keeps_the_original_operation_and_never_reissues_dispatch() -> Test {
    let mut f = Fixture::new()?;
    let prepared = f.prepare("lost-handles")?;
    let operation = prepared.operation().clone();
    let original_digest = prepared.digest();
    drop(prepared);
    let recovered = f
        .effects
        .prepared(&operation)
        .ok_or("preparation missing")?;
    assert_eq!(recovered.digest(), original_digest);
    let inert = recovered.clone();
    let committed = f.commit(recovered)?;
    let before = f.effects.journal().clone();
    let refusal = f
        .effects
        .commit(
            &f.authority,
            &f.tree,
            &mut f.leases,
            inert.clone(),
            TimestampNs(5),
            approval(&inert),
        )
        .expect_err("an inert clone cannot obtain a second dispatch permit");
    assert!(matches!(
        refusal.error(),
        EffectCoordError::IllegalTransition {
            from: EffectState::Committed,
            ..
        }
    ));
    assert_eq!(f.effects.journal(), &before);
    drop(committed);
    let recovered = f
        .effects
        .prepared(&operation)
        .ok_or("committed operation missing")?;
    assert_eq!(f.effects.state(&recovered)?, EffectState::Committed);
    f.effects.reconcile(
        &mut f.tree,
        &f.authority,
        &recovered,
        Reconciliation::Indeterminate("dispatch permit lost; query original request"),
        TimestampNs(5),
    )?;
    let proof = digest(b"independently observed requested pose");
    f.effects.reconcile(
        &mut f.tree,
        &f.authority,
        &recovered,
        Reconciliation::Observed(proof),
        TimestampNs(6),
    )?;
    assert_eq!(
        f.tree.get(f.authority.region())?.obligations[recovered.obligation()].state,
        ObligationState::Indeterminate
    );
    f.effects.reconcile(
        &mut f.tree,
        &f.authority,
        &recovered,
        Reconciliation::Verified(proof),
        TimestampNs(7),
    )?;
    assert_eq!(f.effects.state(&recovered)?, EffectState::Verified);
    assert!(
        f.effects
            .receipt(&recovered)?
            .indeterminate_reason
            .is_some()
    );
    assert_eq!(f.effects.journal().operations().count(), 1);
    assert!(f.authority.finalize_report(&f.tree)?.is_empty());
    Ok(())
}

#[test]
fn verification_matches_retained_observation_and_terminal_retries_are_exact() -> Test {
    let mut f = Fixture::new()?;
    let prepared = f.prepare("proof-match")?;
    let inert = prepared.clone();
    let committed = f.commit(prepared)?;
    let proof = digest(b"camera in approved pose");
    let refusal = f
        .effects
        .verified(&mut f.tree, &f.authority, committed, proof, TimestampNs(5))
        .expect_err("dispatch is not an observation");
    assert!(matches!(
        refusal.error(),
        EffectCoordError::IllegalTransition { .. }
    ));
    let mut committed = refusal.into_token();
    f.effects
        .adapter_accepted(&mut committed, Some(digest(b"adapter ack")), TimestampNs(5))?;
    f.effects.observed(&mut committed, proof, TimestampNs(6))?;
    let before = f.effects.journal().clone();
    let obligations = f.tree.get(f.authority.region())?.obligations.clone();
    let refusal = f
        .effects
        .verified(
            &mut f.tree,
            &f.authority,
            committed,
            digest(b"unrelated evidence"),
            TimestampNs(7),
        )
        .expect_err("verification must match the recorded observation");
    assert!(matches!(
        refusal.error(),
        EffectCoordError::Journal {
            error: ContractError::InvalidDigest,
            ..
        }
    ));
    assert_eq!(f.effects.journal(), &before);
    assert_eq!(f.tree.get(f.authority.region())?.obligations, obligations);
    assert_eq!(
        f.effects.receipt(refusal.token())?.result_digest,
        Some(proof)
    );
    f.effects.verified(
        &mut f.tree,
        &f.authority,
        refusal.into_token(),
        proof,
        TimestampNs(7),
    )?;
    let terminal = f.effects.journal().clone();
    f.effects.reconcile(
        &mut f.tree,
        &f.authority,
        &inert,
        Reconciliation::Verified(proof),
        TimestampNs(8),
    )?;
    assert_eq!(f.effects.journal(), &terminal);
    assert!(
        f.effects
            .reconcile(
                &mut f.tree,
                &f.authority,
                &inert,
                Reconciliation::Verified(digest(b"replacement proof")),
                TimestampNs(9)
            )
            .is_err()
    );
    assert_eq!(f.effects.journal(), &terminal);
    assert_eq!(
        f.tree.get(f.authority.region())?.obligations[inert.obligation()].proof_digest,
        Some(proof)
    );
    Ok(())
}

#[test]
fn cancellation_proof_binds_the_original_preparation_and_exact_cancel_evidence() -> Test {
    let mut f = Fixture::new()?;
    let one = f.prepare("cancel-one")?;
    let two = f.prepare("cancel-two")?;
    let evidence = digest(b"operator withdrew both pending requests");
    let expected_one = f
        .effects
        .journal()
        .cancellation_proof(one.operation(), evidence)?;
    let expected_two = f
        .effects
        .journal()
        .cancellation_proof(two.operation(), evidence)?;
    assert_ne!(expected_one, expected_two);
    f.effects.cancel_prepared(
        &mut f.tree,
        &f.authority,
        one.clone(),
        evidence,
        TimestampNs(4),
    )?;
    f.effects.cancel_prepared(
        &mut f.tree,
        &f.authority,
        two.clone(),
        evidence,
        TimestampNs(4),
    )?;
    for (prepared, expected) in [(&one, expected_one), (&two, expected_two)] {
        assert_eq!(f.effects.receipt(prepared)?.result_digest, Some(expected));
        assert_eq!(
            f.tree.get(f.authority.region())?.obligations[prepared.obligation()].proof_digest,
            Some(expected)
        );
    }
    let before = f.effects.journal().clone();
    f.effects.reconcile(
        &mut f.tree,
        &f.authority,
        &one,
        Reconciliation::Cancelled(evidence),
        TimestampNs(5),
    )?;
    assert_eq!(f.effects.journal(), &before);
    assert!(
        f.effects
            .reconcile(
                &mut f.tree,
                &f.authority,
                &one,
                Reconciliation::Cancelled(digest(b"replacement cancellation")),
                TimestampNs(6)
            )
            .is_err()
    );
    assert_eq!(f.effects.journal(), &before);
    assert!(
        f.effects
            .commit(
                &f.authority,
                &f.tree,
                &mut f.leases,
                one.clone(),
                TimestampNs(7),
                approval(&one)
            )
            .is_err()
    );
    assert!(f.authority.finalize_report(&f.tree)?.is_empty());
    Ok(())
}

#[test]
fn failure_requires_evidence_and_reason_then_preserves_uncertainty_provenance() -> Test {
    let mut f = Fixture::new()?;
    let prepared = f.prepare("failure-proof")?;
    let inert = prepared.clone();
    let committed = f.commit(prepared)?;
    let before = f.effects.journal().clone();
    let refusal = f
        .effects
        .failed(
            &mut f.tree,
            &f.authority,
            committed,
            None,
            "device refused",
            TimestampNs(5),
        )
        .expect_err("failure needs evidence");
    assert!(matches!(
        refusal.error(),
        EffectCoordError::Journal {
            error: ContractError::EvidenceRequired,
            ..
        }
    ));
    assert_eq!(f.effects.journal(), &before);
    let proof = digest(b"device reported requested operation refused");
    let refusal = f
        .effects
        .failed(
            &mut f.tree,
            &f.authority,
            refusal.into_token(),
            Some(proof),
            " ",
            TimestampNs(5),
        )
        .expect_err("failure needs a reason");
    assert_eq!(f.effects.journal(), &before);
    let committed = f.effects.indeterminate(
        &mut f.tree,
        &f.authority,
        refusal.into_token(),
        Some("request acknowledgement lost"),
        TimestampNs(5),
    )?;
    f.effects.failed(
        &mut f.tree,
        &f.authority,
        committed,
        Some(proof),
        "device refused",
        TimestampNs(6),
    )?;
    assert_eq!(f.effects.state(&inert)?, EffectState::Failed);
    assert!(f.effects.receipt(&inert)?.indeterminate_reason.is_some());
    assert_eq!(
        f.tree.get(f.authority.region())?.obligations[inert.obligation()].state,
        ObligationState::Failed
    );
    assert!(
        f.tree
            .get(f.authority.region())?
            .reconciliation_obligations
            .is_empty()
    );
    let terminal = f.effects.journal().clone();
    f.effects.reconcile(
        &mut f.tree,
        &f.authority,
        &inert,
        Reconciliation::Failed {
            proof,
            reason: "device refused",
        },
        TimestampNs(7),
    )?;
    assert_eq!(f.effects.journal(), &terminal);
    assert!(
        f.effects
            .reconcile(
                &mut f.tree,
                &f.authority,
                &inert,
                Reconciliation::Failed {
                    proof,
                    reason: "different reason"
                },
                TimestampNs(8)
            )
            .is_err()
    );
    assert_eq!(f.effects.journal(), &terminal);
    Ok(())
}

#[test]
fn reconciliation_checks_owner_and_live_tree_and_rolls_back_a_conflicting_note() -> Test {
    let mut f = Fixture::new()?;
    let other = Fixture::new()?;
    let prepared = f.prepare("atomic-reconciliation")?;
    let inert = prepared.clone();
    let committed = f.commit(prepared)?;
    let note = "query original adapter operation";
    let _committed = f.effects.indeterminate(
        &mut f.tree,
        &f.authority,
        committed,
        Some(note),
        TimestampNs(5),
    )?;
    let before = f.effects.journal().clone();
    let obligations = f.tree.get(f.authority.region())?.obligations.clone();
    let mut snapshot = f.tree.clone();
    let proof = digest(b"late observed pose");
    assert!(matches!(
        f.effects.reconcile(
            &mut f.tree,
            &other.authority,
            &inert,
            Reconciliation::Observed(proof),
            TimestampNs(6)
        ),
        Err(EffectCoordError::WrongAuthority { .. })
    ));
    assert!(matches!(
        f.effects.reconcile(
            &mut snapshot,
            &f.authority,
            &inert,
            Reconciliation::Observed(proof),
            TimestampNs(6)
        ),
        Err(EffectCoordError::Region { .. })
    ));
    assert_eq!(f.effects.journal(), &before);
    assert_eq!(f.tree.get(f.authority.region())?.obligations, obligations);
    assert_eq!(snapshot.get(f.authority.region())?.obligations, obligations);
    f.effects.reconcile(
        &mut f.tree,
        &f.authority,
        &inert,
        Reconciliation::Observed(proof),
        TimestampNs(6),
    )?;
    let observed = f.effects.journal().clone();
    assert!(
        f.effects
            .reconcile(
                &mut f.tree,
                &f.authority,
                &inert,
                Reconciliation::Indeterminate("replace original reconciliation record"),
                TimestampNs(7)
            )
            .is_err()
    );
    assert_eq!(f.effects.journal(), &observed);
    assert_eq!(
        f.tree.get(f.authority.region())?.reconciliation_obligations[inert.obligation()],
        note
    );
    f.effects.reconcile(
        &mut f.tree,
        &f.authority,
        &inert,
        Reconciliation::Verified(proof),
        TimestampNs(7),
    )?;
    assert!(
        f.tree
            .get(f.authority.region())?
            .reconciliation_obligations
            .is_empty()
    );
    assert_eq!(f.effects.state(&inert)?, EffectState::Verified);
    Ok(())
}

#[test]
fn another_coordinator_cannot_adopt_a_handle_or_duplicate_its_region_obligation() -> Test {
    let mut f = Fixture::new()?;
    let prepared = f.prepare("coordinator-binding")?;
    let operation = prepared.operation().clone();
    let mut other = EffectCoordinator::new();
    assert!(matches!(
        other.state(&prepared),
        Err(EffectCoordError::WrongCoordinator { .. })
    ));
    let approved = approval(&prepared);
    let refusal = other
        .commit(
            &f.authority,
            &f.tree,
            &mut f.leases,
            prepared,
            TimestampNs(4),
            approved,
        )
        .expect_err("only the original coordinator can authorize this operation");
    assert!(matches!(
        refusal.error(),
        EffectCoordError::WrongCoordinator { .. }
    ));
    assert_eq!(f.effects.state(refusal.token())?, EffectState::Prepared);
    assert!(matches!(
        other.prepare(
            &f.authority,
            &mut f.tree,
            &mut f.leases,
            request(&operation, f.fence)?,
            TimestampNs(5)
        ),
        Err(EffectCoordError::DuplicateOperation { .. })
    ));
    assert_eq!(other.journal().operations().count(), 0);
    assert_eq!(f.effects.journal().operations().count(), 1);
    assert_eq!(f.tree.get(f.authority.region())?.obligations.len(), 1);
    f.effects.cancel_prepared(
        &mut f.tree,
        &f.authority,
        refusal.into_token(),
        digest(b"withdraw pending operation"),
        TimestampNs(6),
    )?;
    assert!(f.authority.finalize_report(&f.tree)?.is_empty());
    Ok(())
}

#[test]
fn oversized_failure_and_reconciliation_text_refuses_without_partial_settlement() -> Test {
    let mut f = Fixture::new()?;
    let prepared = f.prepare("bounded-evidence")?;
    let inert = prepared.clone();
    let committed = f.commit(prepared)?;
    let before = f.effects.journal().clone();
    let obligations = f.tree.get(f.authority.region())?.obligations.clone();
    let oversized_reason = "x".repeat(fss_core::effect::MAX_ERROR_CODE_LEN + 1);
    let proof = digest(b"adapter failure evidence");
    let refusal = f
        .effects
        .failed(
            &mut f.tree,
            &f.authority,
            committed,
            Some(proof),
            &oversized_reason,
            TimestampNs(5),
        )
        .expect_err("failure reason exceeds canonical bound");
    assert!(matches!(
        refusal.error(),
        EffectCoordError::Journal {
            error: ContractError::InvalidIdentifier,
            ..
        }
    ));
    assert_eq!(f.effects.journal(), &before);
    assert_eq!(f.tree.get(f.authority.region())?.obligations, obligations);
    let oversized_note = "x".repeat(fss_core::effect::MAX_DETAIL_LEN + 1);
    let refusal = f
        .effects
        .indeterminate(
            &mut f.tree,
            &f.authority,
            refusal.into_token(),
            Some(&oversized_note),
            TimestampNs(5),
        )
        .expect_err("reconciliation note exceeds canonical bound");
    assert!(matches!(
        refusal.error(),
        EffectCoordError::Journal {
            error: ContractError::InvalidIdentifier,
            ..
        }
    ));
    assert_eq!(f.effects.journal(), &before);
    assert_eq!(f.tree.get(f.authority.region())?.obligations, obligations);
    assert!(
        f.tree
            .get(f.authority.region())?
            .reconciliation_obligations
            .is_empty()
    );
    let exact_note = "x".repeat(fss_core::effect::MAX_DETAIL_LEN);
    let committed = f.effects.indeterminate(
        &mut f.tree,
        &f.authority,
        refusal.into_token(),
        Some(&exact_note),
        TimestampNs(5),
    )?;
    let exact_reason = "x".repeat(fss_core::effect::MAX_ERROR_CODE_LEN);
    f.effects.failed(
        &mut f.tree,
        &f.authority,
        committed,
        Some(proof),
        &exact_reason,
        TimestampNs(6),
    )?;
    assert_eq!(f.effects.state(&inert)?, EffectState::Failed);
    assert!(f.authority.finalize_report(&f.tree)?.is_empty());
    Ok(())
}

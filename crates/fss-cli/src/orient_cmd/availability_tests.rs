#![forbid(unsafe_code)]
//! Real custody and graph composition; accounting failures must not partially augment output.

#[path = "../custody_review/fixture.rs"]
mod fixture;

use super::*;
use fixture::{Fixture, TestResult, inventory};
use fss_core::{AgentView, PrincipalId};
use fss_graph_algorithms::evidence_brief::availability::AvailableSupport;
use fss_reference::agent_orient::{
    OrientLimits, OrientRequest, explain_event, orient_deployment, read_deployment,
};

fn support(f: &Fixture) -> TestResult<evidence::SupportReview> {
    let limits = OrientLimits::default();
    let snapshot = read_deployment(&f.root, &limits)?;
    let orientation = orient_deployment(
        &snapshot,
        &OrientRequest {
            view: AgentView::Brief,
            principal: PrincipalId::parse(crate::orient_cmd::DEFAULT_PRINCIPAL)?,
            budget_tokens: None,
        },
        &limits,
    )?;
    let explanation =
        explain_event(&snapshot, &orientation, &f.event.event_id)?.ok_or("missing event")?;
    Ok(evidence::compile(
        &snapshot,
        &orientation,
        &explanation,
        AgentView::Forensic,
        u64::from(AgentView::Forensic.target_tokens()),
    )?)
}
fn custody(f: &Fixture, limits: CustodyAuditLimits) -> TestResult<CustodyReview> {
    let snapshot = read_deployment(&f.root, &OrientLimits::default())?;
    Ok(crate::custody_review::check_event(
        &f.root,
        &snapshot,
        &f.event.event_id,
        limits,
        &|| false,
    )?)
}

#[test]
fn every_custody_state_has_an_explicit_non_promoting_mapping() {
    assert_eq!(
        availability(CustodyObjectState::Verified),
        ObjectAvailability::Verified
    );
    for state in [
        CustodyObjectState::ObjectOverLimit,
        CustodyObjectState::Unreadable,
    ] {
        assert_eq!(availability(state), ObjectAvailability::Unchecked);
    }
    for state in [
        CustodyObjectState::Missing,
        CustodyObjectState::Corrupt,
        CustodyObjectState::InvalidManifest,
        CustodyObjectState::Deleted,
        CustodyObjectState::LocallyTombstoned,
    ] {
        assert_eq!(availability(state), ObjectAvailability::Unavailable);
    }
}

#[test]
fn checked_support_reuses_the_same_graph_and_only_its_remaining_budget() -> TestResult {
    let f = Fixture::new("available-support-join")?;
    let before = inventory(&f.root)?;
    let mut support = support(&f)?;
    let review = custody(&f, CustodyAuditLimits::default())?;
    let remaining = support.graph_remaining;
    assert!(remaining.max_operations < evidence::GRAPH_BUDGET.max_operations);
    assert!(remaining.max_output_entries < evidence::GRAPH_BUDGET.max_output_entries);
    let analysis = conditioned_support(&support, &review)?;
    assert_eq!(analysis.support, AvailableSupport::VerifiedReferencePath);
    assert_eq!(
        support.availability_basis.as_ref().ok_or("basis")?.1,
        *review.basis_anchor()
    );
    // Isolate augmentation's charge from the already covered orientation token estimate.
    support.consumed.tokens = 0;
    augment(&mut support, &review)?;
    assert_eq!(
        support.graph_remaining.max_operations,
        remaining.max_operations - analysis.graph_operations
    );
    assert_eq!(
        support.graph_remaining.max_output_entries,
        remaining.max_output_entries - analysis.graph_output_entries
    );
    assert!(
        support
            .receipt
            .evidence_subgraph()
            .contains(&analysis.possible_witness.digest())
    );
    assert!(
        support
            .receipt
            .evidence_subgraph()
            .contains(&analysis.verified_witness.digest())
    );
    assert!(support.availability_basis.is_none());
    assert_eq!(
        augment(&mut support, &review),
        Err(CustodyReviewError::InvalidBinding)
    );
    assert_eq!(inventory(&f.root)?, before);
    Ok(())
}

#[test]
fn object_size_refusal_is_an_unchecked_path_not_a_lost_source() -> TestResult {
    let f = Fixture::new("availability-object-bound")?;
    let support = support(&f)?;
    let review = custody(
        &f,
        CustodyAuditLimits {
            max_object_bytes: 0,
            ..CustodyAuditLimits::default()
        },
    )?;
    assert!(!review.audit().all_verified());
    assert!(!review.audit().manifest_expansion_complete());
    assert_eq!(
        conditioned_support(&support, &review)?.support,
        AvailableSupport::UncheckedReferencePath
    );
    Ok(())
}

#[test]
fn full_anchor_and_publication_root_must_match_before_graph_work() -> TestResult {
    let f = Fixture::new("availability-bindings")?;
    let review = custody(&f, CustodyAuditLimits::default())?;
    for change in 0..3 {
        let mut support = support(&f)?;
        let (_, anchor, root) = support.availability_basis.as_mut().ok_or("basis")?;
        match change {
            0 => anchor.policy_epoch += 1, // Same state root and subject is still insufficient.
            1 => *root = ContentDigest::sha256(b"different publication"),
            _ => anchor.site_lineage = "site:foreign".to_owned(),
        }
        let receipt = support.receipt.receipt_digest();
        let props = support.propositions.clone();
        let budget = support.graph_remaining;
        assert_eq!(
            augment(&mut support, &review),
            Err(CustodyReviewError::InvalidBinding)
        );
        assert_eq!(support.receipt.receipt_digest(), receipt);
        assert_eq!(support.propositions, props);
        assert_eq!(support.graph_remaining, budget);
    }
    Ok(())
}

#[test]
fn exact_shared_remainder_passes_and_one_short_refuses_without_mutation() -> TestResult {
    let f = Fixture::new("availability-shared-budget")?;
    let review = custody(&f, CustodyAuditLimits::default())?;
    let mut support = support(&f)?;
    let baseline = conditioned_support(&support, &review)?;
    support.graph_remaining = Budget::new(baseline.graph_operations, baseline.graph_output_entries);
    assert_eq!(conditioned_support(&support, &review)?, baseline);
    for budget in [
        Budget::new(baseline.graph_operations - 1, baseline.graph_output_entries),
        Budget::new(baseline.graph_operations, baseline.graph_output_entries - 1),
    ] {
        support.graph_remaining = budget;
        let receipt = support.receipt.receipt_digest();
        let props = support.propositions.clone();
        let consumed = support.consumed;
        assert_eq!(
            augment(&mut support, &review),
            Err(CustodyReviewError::ContextBound)
        );
        assert_eq!(support.receipt.receipt_digest(), receipt);
        assert_eq!(support.propositions, props);
        assert_eq!(support.consumed, consumed);
        assert_eq!(support.graph_remaining, budget);
        assert!(support.availability_basis.is_some());
    }
    Ok(())
}

#[test]
fn semantic_admission_is_exact_and_does_not_drop_a_fault_on_refusal() -> TestResult {
    let f = Fixture::new("availability-semantic-budget")?;
    std::fs::remove_file(f.object_path(f.source))?;
    let review = custody(&f, CustodyAuditLimits::default())?;
    let mut measure = support(&f)?;
    measure.consumed.tokens = 0; // Pure incremental-accounting seam, not a production refund.
    augment(&mut measure, &review)?;
    let charge = measure.consumed.tokens;
    let maximum = measure.requested.tokens;
    assert!(charge > 0 && charge < maximum);
    let mut exact = support(&f)?;
    exact.consumed.tokens = maximum - charge;
    augment(&mut exact, &review)?;
    assert_eq!(exact.consumed.tokens, maximum);
    assert!(
        exact
            .propositions
            .iter()
            .any(|p| p.id.ends_with(&format!(":fault:{}", f.source)))
    );
    let mut over = support(&f)?;
    over.consumed.tokens = maximum - charge + 1;
    let before = over.propositions.clone();
    let receipt = over.receipt.receipt_digest();
    assert_eq!(
        augment(&mut over, &review),
        Err(CustodyReviewError::ContextBound)
    );
    assert_eq!(over.propositions, before);
    assert_eq!(over.receipt.receipt_digest(), receipt);
    assert!(over.availability_basis.is_some());
    Ok(())
}

#[test]
fn graph_faults_have_no_success_or_unchecked_fallback() {
    assert_eq!(
        graph_error(GraphError::Inconsistent("fixture".to_owned()).into()),
        CustodyReviewError::SupportGraph
    );
    assert_eq!(
        graph_error(GraphError::TooLarge.into()),
        CustodyReviewError::ContextBound
    );
    assert_eq!(
        graph_error(
            GraphError::BudgetExhausted {
                dimension: "operations",
                limit: 0
            }
            .into()
        ),
        CustodyReviewError::ContextBound
    );
}

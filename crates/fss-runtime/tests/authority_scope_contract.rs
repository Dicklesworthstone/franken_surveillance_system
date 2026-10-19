#![forbid(unsafe_code)]
//! Multi-camera cancellation, immutable owner binding, and allowance conservation.

use fss_core::{
    BudgetDimension, BudgetVector, BudgetVectorSpec, ContentDigest, ObligationId, OperationId,
    RegionError, RegionId, RegionKind, RegionState, RegionTree, RootAuthoritySpec, RuntimeGrant,
    TaskId, TaskOutcome, TimestampNs,
};
use fss_runtime::authority::{AuthorityCx, AuthorityError};
use fss_runtime::budget::{BudgetLedger, LedgerError, METERED, read_dim};
use fss_runtime::grant::{GrantError, GrantSet};
use fss_runtime::obligation::{ObligationTerminal, new_obligation};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

fn budget(tokens: u64, bytes: u64, cpu_millis: u64) -> BudgetVector {
    let mut result = BudgetVector::ZERO;
    result.tokens = tokens;
    result.bytes = bytes;
    result.cpu_millis = cpu_millis;
    result
}

fn all_budget(quantity: u64) -> Result<BudgetVector, Box<dyn Error>> {
    Ok(BudgetVector::new(BudgetVectorSpec {
        latency_ms: quantity,
        tokens: quantity,
        bytes: quantity,
        model_calls: u32::try_from(quantity)?,
        cpu_millis: quantity,
        accelerator_millis: quantity,
        energy_millijoules: quantity,
        network_bytes: quantity,
        storage_operations: quantity,
        ..BudgetVectorSpec::ZERO
    })?)
}

fn spec(name: &str) -> Result<RootAuthoritySpec, Box<dyn Error>> {
    Ok(RootAuthoritySpec {
        trace_id: "trace:scope".into(),
        operation_id: OperationId::parse(format!("operation:{name}"))?,
        principal: "principal:owner".into(),
        capabilities: vec!["CAP-ADAPTER-NET-001".into()],
        deadline: Some(TimestampNs(1_000_000)),
        priority: 10,
        budgets: all_budget(1_000_000)?,
        privacy_scope: "privacy:local".into(),
        retention_scope: "retention:approved".into(),
        anchor_universe: ContentDigest::sha256(b"scope fixture"),
        generation: 1,
    })
}

fn root() -> Result<(AuthorityCx, RegionTree), Box<dyn Error>> {
    Ok(AuthorityCx::root(
        spec("root")?,
        RegionId::new("region:root")?,
        RegionKind::Process,
        budget(100, 1_000, 10_000),
        TimestampNs(1),
    )?)
}

fn child(
    parent: &mut AuthorityCx,
    tree: &mut RegionTree,
    name: &str,
    kind: RegionKind,
    allowance: BudgetVector,
) -> Result<AuthorityCx, Box<dyn Error>> {
    Ok(parent.scope_down(
        tree,
        RegionId::new(format!("region:{name}"))?,
        kind,
        allowance,
        spec(name)?,
        TimestampNs(2),
    )?)
}

fn close(scope: &AuthorityCx, tree: &mut RegionTree) -> TestResult {
    scope.request_cancellation(tree, TimestampNs(10))?;
    scope.begin_drain(tree, TimestampNs(11))?;
    scope.finalize(tree, TimestampNs(12))?;
    Ok(())
}

#[test]
fn cancelling_one_camera_preserves_parent_and_sibling_authority() -> TestResult {
    let (mut root, mut tree) = root()?;
    let mut property = child(
        &mut root,
        &mut tree,
        "property",
        RegionKind::Property,
        budget(90, 900, 9_000),
    )?;
    let mut first = child(
        &mut property,
        &mut tree,
        "first",
        RegionKind::Sensor,
        budget(30, 300, 3_000),
    )?;
    let mut second = child(
        &mut property,
        &mut tree,
        "second",
        RegionKind::Sensor,
        budget(30, 300, 3_000),
    )?;
    let receiver = child(
        &mut first,
        &mut tree,
        "receiver",
        RegionKind::Receive,
        budget(10, 100, 1_000),
    )?;
    first.request_cancellation(&mut tree, TimestampNs(10))?;
    assert!(first.is_cancel_requested(&tree)?);
    assert!(receiver.is_cancel_requested(&tree)?);
    for scope in [&root, &property, &second] {
        assert!(!scope.is_cancel_requested(&tree)?);
        assert_eq!(tree.get(scope.region())?.state, RegionState::Active);
    }
    let balance = first.budget().remaining();
    let count = tree.region_count();
    assert!(
        child(
            &mut first,
            &mut tree,
            "late",
            RegionKind::Media,
            budget(1, 1, 1)
        )
        .is_err()
    );
    assert!(
        first
            .register_obligation(
                &mut tree,
                new_obligation(
                    "obligation:late",
                    OperationId::parse("operation:first")?,
                    "drained",
                )?
            )
            .is_err()
    );
    assert_eq!(first.budget().remaining(), balance);
    assert_eq!(tree.region_count(), count);
    let other_receiver = child(
        &mut second,
        &mut tree,
        "other",
        RegionKind::Receive,
        budget(10, 100, 1_000),
    )?;
    root.request_cancellation(&mut tree, TimestampNs(20))?;
    for scope in [
        &root,
        &property,
        &first,
        &second,
        &receiver,
        &other_receiver,
    ] {
        assert!(scope.is_cancel_requested(&tree)?);
        assert_eq!(tree.get(scope.region())?.state, RegionState::DrainRequested);
    }
    first.request_cancellation(&mut tree, TimestampNs(30))?;
    assert_eq!(
        tree.get(first.region())?.drain_requested_at,
        Some(TimestampNs(10))
    );
    Ok(())
}

#[test]
fn direct_tree_drain_is_observed_before_any_new_admission() -> TestResult {
    let (mut root, mut tree) = root()?;
    let mut property = child(
        &mut root,
        &mut tree,
        "property",
        RegionKind::Property,
        budget(90, 900, 9_000),
    )?;
    tree.request_drain(root.region(), Some("owner shutdown"), TimestampNs(10))?;
    assert!(property.is_cancel_requested(&tree)?);
    assert!(
        child(
            &mut property,
            &mut tree,
            "late",
            RegionKind::Sensor,
            budget(1, 1, 1)
        )
        .is_err()
    );
    assert_eq!(tree.region_count(), 2);
    Ok(())
}

#[test]
fn child_reservations_conserve_capacity_without_implicit_refunds() -> TestResult {
    let (mut root, mut tree) = root()?;
    let mut property = child(
        &mut root,
        &mut tree,
        "property",
        RegionKind::Property,
        budget(80, 800, 8_000),
    )?;
    property
        .budget_mut(&tree)?
        .spend_vector(&budget(10, 100, 1_000))?;
    let first = child(
        &mut property,
        &mut tree,
        "first",
        RegionKind::Sensor,
        budget(40, 400, 4_000),
    )?;
    assert_eq!(root.budget().remaining(), budget(20, 200, 2_000));
    assert_eq!(property.budget().remaining(), budget(30, 300, 3_000));
    let count = tree.region_count();
    assert!(matches!(
        property.scope_down(
            &mut tree,
            RegionId::new("region:too-large")?,
            RegionKind::Sensor,
            budget(31, 1, 1),
            spec("too-large")?,
            TimestampNs(3),
        ),
        Err(AuthorityError::Budget(LedgerError::Overdraft {
            dimension: BudgetDimension::Tokens,
            requested: 31,
            remaining: 30,
        }))
    ));
    assert_eq!(tree.region_count(), count);
    close(&first, &mut tree)?;
    drop(first);
    assert_eq!(property.budget().remaining(), budget(30, 300, 3_000));
    let second = child(
        &mut property,
        &mut tree,
        "second",
        RegionKind::Sensor,
        budget(30, 300, 3_000),
    )?;
    assert_eq!(second.budget().remaining(), budget(30, 300, 3_000));
    assert_eq!(property.budget().remaining(), BudgetVector::ZERO);
    assert!(
        property
            .budget_mut(&tree)?
            .spend(BudgetDimension::Tokens, 1)
            .is_err()
    );
    Ok(())
}

#[test]
fn refused_tree_attachment_and_scope_changes_do_not_consume_reservations() -> TestResult {
    let (mut root, mut tree) = root()?;
    let mut property = child(
        &mut root,
        &mut tree,
        "property",
        RegionKind::Property,
        budget(80, 800, 8_000),
    )?;
    let _first = child(
        &mut property,
        &mut tree,
        "first",
        RegionKind::Sensor,
        budget(10, 100, 1_000),
    )?;
    let balance = property.budget().remaining();
    let count = tree.region_count();
    assert!(
        child(
            &mut property,
            &mut tree,
            "first",
            RegionKind::Sensor,
            budget(1, 1, 1)
        )
        .is_err()
    );
    assert_eq!(property.budget().remaining(), balance);
    assert_eq!(tree.region_count(), count);
    for field in [
        "trace",
        "principal",
        "capability",
        "privacy",
        "retention",
        "anchor",
        "generation",
        "deadline",
        "priority",
    ] {
        let mut changed = spec("changed")?;
        match field {
            "trace" => changed.trace_id = "trace:other".into(),
            "principal" => changed.principal = "principal:other".into(),
            "capability" => changed.capabilities.push("CAP-PTZ-COMMIT-001".into()),
            "privacy" => changed.privacy_scope = "privacy:public".into(),
            "retention" => changed.retention_scope = "retention:forever".into(),
            "anchor" => changed.anchor_universe = ContentDigest::sha256(b"other anchor"),
            "generation" => changed.generation = 2,
            "deadline" => changed.deadline = None,
            _ => changed.priority = 0,
        }
        assert!(
            property
                .scope_down(
                    &mut tree,
                    RegionId::new("region:changed")?,
                    RegionKind::Sensor,
                    budget(1, 1, 1),
                    changed,
                    TimestampNs(3),
                )
                .is_err(),
            "broadened {field}"
        );
        assert_eq!(property.budget().remaining(), balance);
        assert_eq!(tree.region_count(), count);
    }
    Ok(())
}

#[test]
fn vector_reservation_refuses_atomically_in_all_dimensions() -> TestResult {
    let initial = all_budget(10)?;
    let mut ledger = BudgetLedger::new(initial);
    for dimension in METERED {
        let mut excessive = initial;
        match dimension {
            BudgetDimension::LatencyMs => excessive.latency_ms += 1,
            BudgetDimension::Tokens => excessive.tokens += 1,
            BudgetDimension::Bytes => excessive.bytes += 1,
            BudgetDimension::ModelCalls => excessive.model_calls += 1,
            BudgetDimension::CpuMillis => excessive.cpu_millis += 1,
            BudgetDimension::AcceleratorMillis => excessive.accelerator_millis += 1,
            BudgetDimension::EnergyMillijoules => excessive.energy_millijoules += 1,
            BudgetDimension::NetworkBytes => excessive.network_bytes += 1,
            BudgetDimension::StorageOperations => excessive.storage_operations += 1,
            _ => return Err("unexpected non-metered dimension".into()),
        }
        assert_eq!(
            ledger.spend_vector(&excessive),
            Err(LedgerError::Overdraft {
                dimension,
                requested: 11,
                remaining: 10,
            })
        );
        assert_eq!(ledger.remaining(), initial);
    }
    let limit = BudgetVector::new(BudgetVectorSpec {
        latency_ms: u64::MAX,
        tokens: u64::MAX,
        bytes: u64::MAX,
        model_calls: u32::MAX,
        cpu_millis: u64::MAX,
        accelerator_millis: u64::MAX,
        energy_millijoules: u64::MAX,
        network_bytes: u64::MAX,
        storage_operations: u64::MAX,
        ..BudgetVectorSpec::ZERO
    })?;
    let mut maximum = BudgetLedger::new(limit);
    maximum.spend_vector(&limit)?;
    assert_eq!(maximum.remaining(), BudgetVector::ZERO);
    for dimension in METERED {
        assert_eq!(
            read_dim(maximum.consumed(), dimension),
            read_dim(&limit, dimension)
        );
        assert!(maximum.spend(dimension, 1).is_err());
    }
    Ok(())
}

#[test]
fn closed_child_returns_only_unused_capacity_once_without_touching_siblings() -> TestResult {
    let (mut process, mut tree) = AuthorityCx::root(
        spec("root")?,
        RegionId::new("region:root")?,
        RegionKind::Process,
        all_budget(100)?,
        TimestampNs(1),
    )?;
    let mut property = child(
        &mut process,
        &mut tree,
        "property",
        RegionKind::Property,
        all_budget(100)?,
    )?;
    let mut first = child(
        &mut property,
        &mut tree,
        "first",
        RegionKind::Sensor,
        all_budget(60)?,
    )?;
    let second = child(
        &mut property,
        &mut tree,
        "second",
        RegionKind::Sensor,
        all_budget(40)?,
    )?;
    first.budget_mut(&tree)?.spend_vector(&all_budget(20)?)?;
    assert_eq!(property.pressure(), fss_core::ResourcePressure::Critical);
    for step in 0..3 {
        assert!(
            property
                .release_scope_reservation(&tree, &mut first)
                .is_err()
        );
        assert_eq!(property.budget().remaining(), BudgetVector::ZERO);
        if step == 0 {
            first.request_cancellation(&mut tree, TimestampNs(10))?;
        }
        if step == 1 {
            first.begin_drain(&mut tree, TimestampNs(11))?;
        }
    }
    first.finalize(&mut tree, TimestampNs(12))?;
    assert_eq!(
        property.release_scope_reservation(&tree, &mut first)?,
        all_budget(40)?
    );
    assert_eq!(property.budget().remaining(), all_budget(40)?);
    assert_eq!(*property.budget().consumed(), all_budget(60)?);
    assert_eq!(property.pressure(), fss_core::ResourcePressure::Elevated);
    assert_eq!(second.budget().remaining(), all_budget(40)?);
    assert_eq!(*first.budget().consumed(), all_budget(20)?);
    assert!(matches!(
        property.release_scope_reservation(&tree, &mut first),
        Err(AuthorityError::ReservationReleased)
    ));
    assert!(matches!(
        first.budget_mut(&tree),
        Err(AuthorityError::ReservationReleased)
    ));
    assert!(
        child(
            &mut property,
            &mut tree,
            "large",
            RegionKind::Sensor,
            all_budget(41)?
        )
        .is_err()
    );
    let third = child(
        &mut property,
        &mut tree,
        "third",
        RegionKind::Sensor,
        all_budget(40)?,
    )?;
    assert_eq!(third.budget().remaining(), all_budget(40)?);
    assert_eq!(property.budget().remaining(), BudgetVector::ZERO);
    Ok(())
}

#[test]
fn independent_equal_roots_cannot_settle_each_others_children() -> TestResult {
    let (mut first_root, mut first_tree) = root()?;
    let _first_child = child(
        &mut first_root,
        &mut first_tree,
        "property",
        RegionKind::Property,
        budget(80, 800, 8_000),
    )?;
    let (mut second_root, mut second_tree) = root()?;
    let mut second_child = child(
        &mut second_root,
        &mut second_tree,
        "property",
        RegionKind::Property,
        budget(80, 800, 8_000),
    )?;
    close(&second_child, &mut second_tree)?;
    assert!(matches!(
        first_root.release_scope_reservation(&second_tree, &mut second_child),
        Err(AuthorityError::ScopeMismatch)
    ));
    assert_eq!(first_root.budget().remaining(), budget(20, 200, 2_000));
    assert_eq!(second_root.budget().remaining(), budget(20, 200, 2_000));
    second_root.release_scope_reservation(&second_tree, &mut second_child)?;
    assert_eq!(second_root.budget().remaining(), budget(100, 1_000, 10_000));
    Ok(())
}

#[test]
fn descendant_settlements_preserve_consumed_work_through_closed_parents() -> TestResult {
    let (mut root, mut tree) = root()?;
    let mut property = child(
        &mut root,
        &mut tree,
        "property",
        RegionKind::Property,
        budget(80, 800, 8_000),
    )?;
    let mut camera = child(
        &mut property,
        &mut tree,
        "camera",
        RegionKind::Sensor,
        budget(40, 400, 4_000),
    )?;
    property
        .budget_mut(&tree)?
        .spend_vector(&budget(10, 100, 1_000))?;
    camera
        .budget_mut(&tree)?
        .spend_vector(&budget(10, 100, 1_000))?;
    root.request_cancellation(&mut tree, TimestampNs(10))?;
    for scope in [&camera, &property, &root] {
        scope.begin_drain(&mut tree, TimestampNs(11))?;
        scope.finalize(&mut tree, TimestampNs(12))?;
    }
    assert_eq!(
        property.release_scope_reservation(&tree, &mut camera)?,
        budget(30, 300, 3_000)
    );
    assert_eq!(
        root.release_scope_reservation(&tree, &mut property)?,
        budget(60, 600, 6_000)
    );
    assert_eq!(root.budget().remaining(), budget(80, 800, 8_000));
    assert_eq!(*root.budget().consumed(), budget(20, 200, 2_000));
    assert!(
        property
            .release_scope_reservation(&tree, &mut camera)
            .is_err()
    );
    Ok(())
}

#[test]
fn local_empty_leak_report_cannot_close_live_children_or_tasks() -> TestResult {
    let (mut root, mut tree) = root()?;
    let property = child(
        &mut root,
        &mut tree,
        "property",
        RegionKind::Property,
        budget(80, 800, 8_000),
    )?;
    let task = TaskId::new("task:owned")?;
    tree.register_task(property.region(), task.clone(), TimestampNs(3))?;
    let obligation = ObligationId::parse("obligation:reconcile")?;
    property.register_obligation(
        &mut tree,
        new_obligation(
            obligation.as_str(),
            OperationId::parse("operation:property")?,
            "reconcile cancelled publication",
        )?,
    )?;
    assert!(root.finalize_report(&tree)?.is_empty());
    assert!(root.finalize(&mut tree, TimestampNs(4)).is_err());
    root.request_cancellation(&mut tree, TimestampNs(10))?;
    for scope in [&root, &property] {
        scope.begin_drain(&mut tree, TimestampNs(11))?;
    }
    assert!(matches!(
        root.finalize(&mut tree, TimestampNs(12)),
        Err(AuthorityError::Region(RegionError::ChildNotDrained { .. }))
    ));
    assert!(property.finalize(&mut tree, TimestampNs(12)).is_err());
    tree.complete_task(
        property.region(),
        &task,
        TaskOutcome::Cancelled,
        TimestampNs(13),
    )?;
    assert!(property.finalize(&mut tree, TimestampNs(14)).is_err());
    assert!(
        property
            .resolve_obligation(
                &mut tree,
                &obligation,
                ObligationTerminal::Indeterminate,
                None,
                None
            )
            .is_err()
    );
    assert_eq!(property.leaked_obligations(&tree)?.len(), 1);
    property.resolve_obligation(
        &mut tree,
        &obligation,
        ObligationTerminal::Indeterminate,
        None,
        Some("reconciliation:lookup"),
    )?;
    let child_proof = property.finalize(&mut tree, TimestampNs(15))?;
    let root_proof = root.finalize(&mut tree, TimestampNs(16))?;
    for proof in [child_proof, root_proof] {
        assert_eq!(proof.total_tasks, 1);
        assert_eq!(proof.total_obligations, 1);
        assert_eq!(proof.indeterminate_obligations, 1);
    }
    assert!(root.finalize(&mut tree, TimestampNs(17)).is_err());
    Ok(())
}

#[test]
fn mismatched_or_missing_tree_never_reports_clean_or_acquires_authority() -> TestResult {
    let (authority, _) = root()?;
    let mut other_spec = spec("root")?;
    other_spec.principal = "principal:other".into();
    let (_, mut other) = AuthorityCx::root(
        other_spec,
        authority.region().clone(),
        RegionKind::Process,
        budget(1, 1, 1),
        TimestampNs(1),
    )?;
    assert!(matches!(
        authority.finalize_report(&other),
        Err(AuthorityError::ScopeMismatch)
    ));
    assert!(
        authority
            .request_cancellation(&mut other, TimestampNs(2))
            .is_err()
    );
    assert_eq!(other.get(authority.region())?.state, RegionState::Active);
    let (_, missing) = AuthorityCx::root(
        spec("other")?,
        RegionId::new("region:other")?,
        RegionKind::Process,
        BudgetVector::ZERO,
        TimestampNs(1),
    )?;
    assert!(matches!(
        authority.leaked_obligations(&missing),
        Err(AuthorityError::ScopeMismatch)
    ));
    assert!(authority.is_cancel_requested(&missing).is_err());
    Ok(())
}

#[test]
fn root_kind_and_immutable_authority_must_be_valid_before_construction() -> TestResult {
    assert!(
        AuthorityCx::root(
            spec("bad")?,
            RegionId::new("region:bad")?,
            RegionKind::Sensor,
            BudgetVector::ZERO,
            TimestampNs(1),
        )
        .is_err()
    );
    let mut invalid = spec("bad")?;
    invalid.generation = 0;
    assert!(matches!(
        AuthorityCx::root(
            invalid,
            RegionId::new("region:bad")?,
            RegionKind::Process,
            BudgetVector::ZERO,
            TimestampNs(1),
        ),
        Err(AuthorityError::Contract(_))
    ));
    Ok(())
}

#[test]
fn canonical_allowance_ceilings_cover_every_dimension_before_root_or_child_mutation() -> TestResult
{
    let ceiling = BudgetVectorSpec {
        latency_ms: 10,
        tokens: 10,
        bytes: 10,
        model_calls: 10,
        cpu_millis: 10,
        accelerator_millis: 10,
        energy_millijoules: 10,
        network_bytes: 10,
        storage_operations: 10,
        privacy_exposure: 10.0,
        operator_attention_seconds: 10.0,
    };
    for dimension in METERED.into_iter().chain([
        BudgetDimension::PrivacyExposure,
        BudgetDimension::OperatorAttentionSeconds,
    ]) {
        let mut excessive = ceiling;
        match dimension {
            BudgetDimension::LatencyMs => excessive.latency_ms += 1,
            BudgetDimension::Tokens => excessive.tokens += 1,
            BudgetDimension::Bytes => excessive.bytes += 1,
            BudgetDimension::ModelCalls => excessive.model_calls += 1,
            BudgetDimension::CpuMillis => excessive.cpu_millis += 1,
            BudgetDimension::AcceleratorMillis => excessive.accelerator_millis += 1,
            BudgetDimension::EnergyMillijoules => excessive.energy_millijoules += 1,
            BudgetDimension::NetworkBytes => excessive.network_bytes += 1,
            BudgetDimension::StorageOperations => excessive.storage_operations += 1,
            BudgetDimension::PrivacyExposure => excessive.privacy_exposure += 1.0,
            BudgetDimension::OperatorAttentionSeconds => {
                excessive.operator_attention_seconds += 1.0
            }
        }
        let mut limited = spec("limited")?;
        limited.budgets = BudgetVector::new(ceiling)?;
        assert!(
            matches!(
                AuthorityCx::root(
                    limited.clone(),
                    RegionId::new("region:limited")?,
                    RegionKind::Process,
                    BudgetVector::new(excessive)?,
                    TimestampNs(1),
                ),
                Err(AuthorityError::IllegalScope { .. })
            ),
            "root accepted {dimension:?}"
        );
        let parent_budget = BudgetVector::new(BudgetVectorSpec {
            latency_ms: 100,
            tokens: 100,
            bytes: 100,
            model_calls: 100,
            cpu_millis: 100,
            accelerator_millis: 100,
            energy_millijoules: 100,
            network_bytes: 100,
            storage_operations: 100,
            privacy_exposure: 100.0,
            operator_attention_seconds: 100.0,
        })?;
        let mut parent_spec = spec("root")?;
        parent_spec.budgets = parent_budget;
        let (mut parent, mut tree) = AuthorityCx::root(
            parent_spec,
            RegionId::new("region:root")?,
            RegionKind::Process,
            parent_budget,
            TimestampNs(1),
        )?;
        assert!(
            matches!(
                parent.scope_down(
                    &mut tree,
                    RegionId::new("region:limited")?,
                    RegionKind::Property,
                    BudgetVector::new(excessive)?,
                    limited.clone(),
                    TimestampNs(2),
                ),
                Err(AuthorityError::IllegalScope { .. })
            ),
            "child accepted {dimension:?}"
        );
        assert_eq!(parent.budget().remaining(), parent_budget);
        assert_eq!(tree.region_count(), 1);
        let mut accepted = parent.scope_down(
            &mut tree,
            RegionId::new("region:limited")?,
            RegionKind::Property,
            limited.budgets,
            limited,
            TimestampNs(3),
        )?;
        close(&accepted, &mut tree)?;
        parent.release_scope_reservation(&tree, &mut accepted)?;
        assert_eq!(parent.budget().remaining(), parent_budget);
    }
    Ok(())
}

#[test]
fn resource_scopes_are_inherited_and_can_only_narrow_further() -> TestResult {
    let (mut root, mut tree) = root()?;
    root.narrow_grants(
        GrantSet::empty().with_scope(
            RuntimeGrant::AdapterNet,
            ["camera:porch".into(), "camera:garage".into()]
                .into_iter()
                .collect(),
        ),
    )?;
    let mut property = child(
        &mut root,
        &mut tree,
        "property",
        RegionKind::Property,
        budget(80, 800, 8_000),
    )?;
    property.require_grant_for(RuntimeGrant::AdapterNet, "camera:porch")?;
    property.require_grant_for(RuntimeGrant::AdapterNet, "camera:garage")?;
    assert!(matches!(
        property.require_grant_for(RuntimeGrant::AdapterNet, "camera:street"),
        Err(GrantError::OutsideScope { .. })
    ));
    let inherited = property.grants().clone();
    assert!(
        property
            .narrow_grants(GrantSet::empty().with_scope(
                RuntimeGrant::AdapterNet,
                ["camera:street".into()].into_iter().collect(),
            ))
            .is_err()
    );
    assert_eq!(property.grants(), &inherited);
    property.narrow_grants(GrantSet::empty().with_scope(
        RuntimeGrant::AdapterNet,
        ["camera:porch".into()].into_iter().collect(),
    ))?;
    let mut camera = child(
        &mut property,
        &mut tree,
        "porch",
        RegionKind::Sensor,
        budget(20, 200, 2_000),
    )?;
    camera.require_grant_for(RuntimeGrant::AdapterNet, "camera:porch")?;
    assert!(matches!(
        camera.require_grant_for(RuntimeGrant::AdapterNet, "camera:garage"),
        Err(GrantError::OutsideScope { .. })
    ));
    camera.narrow_grants(GrantSet::empty())?;
    let balance = camera.budget().remaining();
    let count = tree.region_count();
    assert!(matches!(
        camera.scope_down(
            &mut tree,
            RegionId::new("region:receiver")?,
            RegionKind::Receive,
            budget(1, 1, 1),
            spec("receiver")?,
            TimestampNs(3),
        ),
        Err(AuthorityError::Grant(GrantError::Widening { .. }))
    ));
    assert_eq!(camera.budget().remaining(), balance);
    assert_eq!(tree.region_count(), count);
    let mut no_caps = spec("receiver")?;
    no_caps.capabilities.clear();
    let receiver = camera.scope_down(
        &mut tree,
        RegionId::new("region:receiver")?,
        RegionKind::Receive,
        budget(1, 1, 1),
        no_caps,
        TimestampNs(4),
    )?;
    assert!(receiver.grants().is_empty());
    Ok(())
}

#[test]
fn cloned_tree_cannot_hide_cancellation_or_authorize_work_and_cleanup() -> TestResult {
    let (mut root, mut tree) = root()?;
    let mut property = child(
        &mut root,
        &mut tree,
        "property",
        RegionKind::Property,
        budget(80, 800, 8_000),
    )?;
    let mut stale = tree.clone();
    root.request_cancellation(&mut tree, TimestampNs(10))?;
    let balance = property.budget().remaining();
    assert!(matches!(
        property.is_cancel_requested(&stale),
        Err(AuthorityError::ScopeMismatch)
    ));
    assert!(matches!(
        property.budget_mut(&stale),
        Err(AuthorityError::ScopeMismatch)
    ));
    assert!(matches!(
        property.finalize_report(&stale),
        Err(AuthorityError::ScopeMismatch)
    ));
    assert!(matches!(
        property.leaked_obligations(&stale),
        Err(AuthorityError::ScopeMismatch)
    ));
    assert!(matches!(
        property.scope_down(
            &mut stale,
            RegionId::new("region:late")?,
            RegionKind::Sensor,
            budget(1, 1, 1),
            spec("late")?,
            TimestampNs(11),
        ),
        Err(AuthorityError::ScopeMismatch)
    ));
    assert!(matches!(
        property.register_obligation(
            &mut stale,
            new_obligation(
                "obligation:late",
                OperationId::parse("operation:property")?,
                "drain",
            )?
        ),
        Err(AuthorityError::ScopeMismatch)
    ));
    assert!(matches!(
        property.resolve_obligation(
            &mut stale,
            &ObligationId::parse("obligation:late")?,
            ObligationTerminal::Drained,
            None,
            None,
        ),
        Err(AuthorityError::ScopeMismatch)
    ));
    assert!(matches!(
        property.request_cancellation(&mut stale, TimestampNs(12)),
        Err(AuthorityError::ScopeMismatch)
    ));
    assert!(matches!(
        property.begin_drain(&mut stale, TimestampNs(12)),
        Err(AuthorityError::ScopeMismatch)
    ));
    assert!(matches!(
        property.finalize(&mut stale, TimestampNs(12)),
        Err(AuthorityError::ScopeMismatch)
    ));
    assert_eq!(property.budget().remaining(), balance);
    assert_eq!(stale.region_count(), 2);
    assert_eq!(stale.get(property.region())?.state, RegionState::Active);
    assert!(property.is_cancel_requested(&tree)?);
    Ok(())
}

#[test]
fn cloned_quiescence_proof_cannot_refund_live_work() -> TestResult {
    let (mut root, mut tree) = root()?;
    let mut property = child(
        &mut root,
        &mut tree,
        "property",
        RegionKind::Property,
        budget(80, 800, 8_000),
    )?;
    let mut stale = tree.clone();
    let task = TaskId::new("task:live")?;
    tree.register_task(property.region(), task.clone(), TimestampNs(3))?;
    stale.request_drain(
        property.region(),
        Some("snapshot shutdown"),
        TimestampNs(10),
    )?;
    stale.begin_drain(property.region(), TimestampNs(11))?;
    assert_eq!(
        stale
            .finalize(property.region(), TimestampNs(12))?
            .total_tasks,
        0
    );
    assert!(matches!(
        root.release_scope_reservation(&stale, &mut property),
        Err(AuthorityError::ScopeMismatch)
    ));
    assert_eq!(root.budget().remaining(), budget(20, 200, 2_000));
    assert_eq!(tree.get(property.region())?.active_tasks.len(), 1);
    assert_eq!(tree.get(property.region())?.state, RegionState::Active);
    property.request_cancellation(&mut tree, TimestampNs(13))?;
    property.begin_drain(&mut tree, TimestampNs(14))?;
    assert!(property.finalize(&mut tree, TimestampNs(15)).is_err());
    tree.complete_task(
        property.region(),
        &task,
        TaskOutcome::Cancelled,
        TimestampNs(16),
    )?;
    assert_eq!(
        property.finalize(&mut tree, TimestampNs(17))?.total_tasks,
        1
    );
    root.release_scope_reservation(&tree, &mut property)?;
    assert_eq!(root.budget().remaining(), budget(100, 1_000, 10_000));
    Ok(())
}

#[test]
fn canonical_closure_ends_spending_but_drain_allows_bounded_cleanup() -> TestResult {
    let (mut root, mut tree) = root()?;
    root.request_cancellation(&mut tree, TimestampNs(10))?;
    root.budget_mut(&tree)?.spend(BudgetDimension::Bytes, 10)?;
    root.begin_drain(&mut tree, TimestampNs(11))?;
    root.budget_mut(&tree)?.spend(BudgetDimension::Bytes, 10)?;
    tree.finalize(root.region(), TimestampNs(12))?;
    let remaining = root.budget().remaining();
    assert!(matches!(
        root.budget_mut(&tree),
        Err(AuthorityError::Region(RegionError::OrphanWork {
            state: RegionState::Closed,
            ..
        },))
    ));
    assert_eq!(root.budget().remaining(), remaining);
    assert_eq!(root.budget().consumed().bytes, 20);
    Ok(())
}

#[test]
fn ancestor_settlement_refuses_until_every_descendant_reservation_is_accounted_for() -> TestResult {
    let (mut root, mut tree) = root()?;
    let mut property = child(
        &mut root,
        &mut tree,
        "property",
        RegionKind::Property,
        budget(80, 800, 8_000),
    )?;
    let mut camera = child(
        &mut property,
        &mut tree,
        "camera",
        RegionKind::Sensor,
        budget(40, 400, 4_000),
    )?;
    camera
        .budget_mut(&tree)?
        .spend_vector(&budget(10, 100, 1_000))?;
    root.request_cancellation(&mut tree, TimestampNs(10))?;
    for scope in [&camera, &property, &root] {
        scope.begin_drain(&mut tree, TimestampNs(11))?;
        scope.finalize(&mut tree, TimestampNs(12))?;
    }
    for _ in 0..2 {
        assert!(matches!(
            root.release_scope_reservation(&tree, &mut property),
            Err(AuthorityError::OutstandingReservations { count: 1 })
        ));
        assert_eq!(root.budget().remaining(), budget(20, 200, 2_000));
        assert_eq!(property.budget().remaining(), budget(40, 400, 4_000));
    }
    property.release_scope_reservation(&tree, &mut camera)?;
    assert_eq!(property.budget().remaining(), budget(70, 700, 7_000));
    assert!(matches!(
        property.release_scope_reservation(&tree, &mut camera),
        Err(AuthorityError::ReservationReleased)
    ));
    root.release_scope_reservation(&tree, &mut property)?;
    assert_eq!(root.budget().remaining(), budget(90, 900, 9_000));
    assert_eq!(*root.budget().consumed(), budget(10, 100, 1_000));
    Ok(())
}

#[test]
fn sibling_authority_cannot_refund_another_scopes_reservation() -> TestResult {
    let (mut root, mut tree) = root()?;
    let mut property = child(
        &mut root,
        &mut tree,
        "property",
        RegionKind::Property,
        budget(80, 800, 8_000),
    )?;
    let mut first = child(
        &mut property,
        &mut tree,
        "first",
        RegionKind::Sensor,
        budget(40, 400, 4_000),
    )?;
    let mut second = child(
        &mut property,
        &mut tree,
        "second",
        RegionKind::Sensor,
        budget(40, 400, 4_000),
    )?;
    let mut receiver = child(
        &mut first,
        &mut tree,
        "receiver",
        RegionKind::Receive,
        budget(10, 100, 1_000),
    )?;
    close(&receiver, &mut tree)?;
    assert!(matches!(
        second.release_scope_reservation(&tree, &mut receiver),
        Err(AuthorityError::ReservationOwnerMismatch)
    ));
    assert_eq!(second.budget().remaining(), budget(40, 400, 4_000));
    first.release_scope_reservation(&tree, &mut receiver)?;
    assert_eq!(first.budget().remaining(), budget(40, 400, 4_000));
    Ok(())
}

#[test]
fn dropped_child_reservations_remain_charged_after_canonical_quiescence() -> TestResult {
    let (mut root, mut tree) = root()?;
    let mut property = child(
        &mut root,
        &mut tree,
        "property",
        RegionKind::Property,
        budget(80, 800, 8_000),
    )?;
    let camera = child(
        &mut property,
        &mut tree,
        "camera",
        RegionKind::Sensor,
        budget(40, 400, 4_000),
    )?;
    root.request_cancellation(&mut tree, TimestampNs(10))?;
    for scope in [&camera, &property] {
        scope.begin_drain(&mut tree, TimestampNs(11))?;
        scope.finalize(&mut tree, TimestampNs(12))?;
    }
    drop(camera);
    assert!(matches!(
        root.release_scope_reservation(&tree, &mut property),
        Err(AuthorityError::OutstandingReservations { count: 1 })
    ));
    assert_eq!(root.budget().remaining(), budget(20, 200, 2_000));
    assert_eq!(property.budget().remaining(), budget(40, 400, 4_000));
    Ok(())
}

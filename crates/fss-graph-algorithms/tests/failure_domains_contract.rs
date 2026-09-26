#![forbid(unsafe_code)]
//! Shared failures are compared with physical vertex removal, not a second contraction.
use std::collections::BTreeSet;

use fss_graph_algorithms::failure_domains::{
    FailureDomain, FailureDomainKind, MAX_FAILURE_DOMAINS, analyse_failure_domains,
};
use fss_graph_algorithms::{
    CoverageObservation, GraphBudget, GraphError, SensorCoverageProjection,
};

fn budget() -> GraphBudget {
    GraphBudget {
        max_operations: 1_000_000,
        max_output_entries: 100_000,
    }
}

fn domain(
    kind: FailureDomainKind,
    id: &str,
    members: &[&str],
) -> Result<FailureDomain, GraphError> {
    FailureDomain::new(
        kind,
        id,
        &members
            .iter()
            .map(|id| (*id).to_owned())
            .collect::<Vec<_>>(),
    )
}

fn projection(rows: &[(&str, &str, u64)]) -> Result<SensorCoverageProjection, GraphError> {
    SensorCoverageProjection::build(
        "site",
        &rows
            .iter()
            .map(|(sensor, zone, count)| CoverageObservation {
                sensor_id: (*sensor).to_owned(),
                zone_scope: (*zone).to_owned(),
                witnesses: *count,
            })
            .collect::<Vec<_>>(),
    )
}

fn reachable(
    projection: &SensorCoverageProjection,
    removed: &BTreeSet<String>,
) -> Result<BTreeSet<String>, GraphError> {
    let graph = &projection.graph;
    let root = graph
        .index_of(&projection.plane)
        .ok_or_else(|| GraphError::UnknownNode(projection.plane.clone()))?;
    let mut reached = BTreeSet::from([root]);
    let mut queue = vec![root];
    while let Some(node) = queue.pop() {
        for &(other, _) in graph.neighbours(node) {
            if !removed.contains(graph.id(other)) && reached.insert(other) {
                queue.push(other);
            }
        }
    }
    Ok(reached
        .into_iter()
        .filter_map(|node| graph.id(node).strip_prefix("zone/").map(str::to_owned))
        .collect())
}

#[test]
fn every_three_sensor_three_zone_graph_matches_simultaneous_removal() -> Result<(), GraphError> {
    let sensors = ["a", "b", "c"];
    let zones = ["zone:x", "zone:y", "ground-zone:z"];
    for bits in 0_u16..512 {
        let mut rows = Vec::new();
        for (i, sensor) in sensors.iter().enumerate() {
            for (j, zone) in zones.iter().enumerate() {
                rows.push((*sensor, *zone, u64::from(bits & (1 << (i * 3 + j)) != 0)));
            }
        }
        let original = projection(&rows)?;
        let before = reachable(&original, &BTreeSet::new())?;
        for members in 1_u8..8 {
            let names: Vec<&str> = sensors
                .iter()
                .enumerate()
                .filter(|(i, _)| members & (1 << i) != 0)
                .map(|(_, name)| *name)
                .collect();
            let declared = domain(FailureDomainKind::Network, "switch", &names)?;
            let removed: BTreeSet<String> =
                names.iter().map(|name| format!("sensor/{name}")).collect();
            let after = reachable(&original, &removed)?;
            let expected: Vec<String> = before.difference(&after).cloned().collect();
            let result = analyse_failure_domains(&original, &[declared], budget())?;
            assert_eq!(result.scenarios.len(), 1);
            assert_eq!(
                result.scenarios[0].lost_zones, expected,
                "edges={bits}, members={members}"
            );
            let counters = &result.scenarios[0].analysis;
            assert_eq!(counters.input_digest, result.scenarios[0].graph.digest());
            counters.bound.check(
                &counters.counters,
                counters.output.articulation_points.len() as u64,
                counters.output.bridges.len() as u64,
            )?;
        }
    }
    Ok(())
}

#[test]
fn overlapping_power_and_network_groups_are_not_alternate_routes() -> Result<(), GraphError> {
    let original = projection(&[("a", "zone:x", 1), ("b", "zone:x", 1), ("c", "zone:y", 1)])?;
    let network = domain(FailureDomainKind::Network, "shared", &["a", "b"])?;
    let power = domain(FailureDomainKind::Power, "shared", &["b", "c"])?;
    let result = analyse_failure_domains(&original, &[power.clone(), network.clone()], budget())?;
    assert_eq!(result.scenarios[0].lost_zones, ["zone:x"]);
    assert_eq!(result.scenarios[1].lost_zones, ["zone:y"]);
    assert_eq!(
        result,
        analyse_failure_domains(&original, &[network, power], budget())?
    );
    Ok(())
}

#[test]
fn membership_order_is_canonical_and_zero_witness_members_are_digest_bound()
-> Result<(), GraphError> {
    let original = projection(&[("a", "zone:x", 1), ("b", "zone:x", 0), ("c", "zone:x", 0)])?;
    let ab = domain(FailureDomainKind::Host, "recorder", &["a", "b"])?;
    let ba = domain(FailureDomainKind::Host, "recorder", &["b", "a"])?;
    let ac = domain(FailureDomainKind::Host, "recorder", &["a", "c"])?;
    let first = analyse_failure_domains(&original, &[ab], budget())?;
    assert_eq!(first, analyse_failure_domains(&original, &[ba], budget())?);
    let changed = analyse_failure_domains(&original, &[ac], budget())?;
    assert_eq!(
        first.scenarios[0].lost_zones,
        changed.scenarios[0].lost_zones
    );
    assert_ne!(
        first.scenarios[0].analysis.input_digest,
        changed.scenarios[0].analysis.input_digest
    );
    Ok(())
}

#[test]
fn unknown_duplicate_empty_and_oversized_declarations_fail_closed() -> Result<(), GraphError> {
    let original = projection(&[("a", "zone:x", 1)])?;
    let known = domain(FailureDomainKind::Clock, "clock", &["a"])?;
    let unknown = domain(FailureDomainKind::Clock, "clock", &["missing"])?;
    assert!(matches!(
        analyse_failure_domains(&original, &[unknown], budget()),
        Err(GraphError::UnknownNode(_))
    ));
    assert!(matches!(
        analyse_failure_domains(&original, &[known.clone(), known.clone()], budget()),
        Err(GraphError::DuplicateNode(_))
    ));
    assert!(matches!(
        analyse_failure_domains(&original, &vec![known; MAX_FAILURE_DOMAINS + 1], budget()),
        Err(GraphError::TooLarge)
    ));
    assert!(domain(FailureDomainKind::Clock, "", &["a"]).is_err());
    assert!(domain(FailureDomainKind::Clock, "bad\nlabel", &["a"]).is_err());
    assert!(domain(FailureDomainKind::Clock, &"x".repeat(65), &["a"]).is_err());
    assert!(domain(FailureDomainKind::Clock, "clock", &[]).is_err());
    assert!(domain(FailureDomainKind::Clock, "clock", &["a", "a"]).is_err());
    assert!(domain(FailureDomainKind::Clock, "clock", &[""]).is_err());
    Ok(())
}

#[test]
fn budgets_are_aggregate_and_never_return_a_partial_scenario_list() -> Result<(), GraphError> {
    let original = projection(&[("a", "zone:x", 1)])?;
    let one = domain(FailureDomainKind::Clock, "one", &["a"])?;
    let two = domain(FailureDomainKind::Clock, "two", &["a"])?;
    let measured = analyse_failure_domains(&original, std::slice::from_ref(&one), budget())?;
    let operations = measured.operations * 2 - 1;
    let limited = GraphBudget {
        max_operations: operations,
        ..budget()
    };
    assert!(matches!(
        analyse_failure_domains(&original, &[one.clone(), two], limited),
        Err(GraphError::BudgetExhausted { .. })
    ));
    let limited = GraphBudget {
        max_output_entries: 0,
        ..budget()
    };
    assert!(matches!(
        analyse_failure_domains(&original, &[one], limited),
        Err(GraphError::BudgetExhausted { .. })
    ));
    Ok(())
}

#[test]
fn a_substituted_public_graph_is_rejected() -> Result<(), GraphError> {
    let mut original = projection(&[("a", "zone:x", 1)])?;
    original.graph = projection(&[("a", "zone:x", 0)])?.graph;
    let declared = domain(FailureDomainKind::Power, "circuit", &["a"])?;
    assert!(matches!(
        analyse_failure_domains(&original, &[declared], budget()),
        Err(GraphError::Inconsistent(_))
    ));
    Ok(())
}

#![forbid(unsafe_code)]
//! Exact declared-demand routing checked by exhaustive integral flows on the physical topology.

mod common;

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use common::{Rng, TestResult};
use fss_core::{CanonicalEncoder, ContentDigest, LedgerAnchor};
use fss_graph_algorithms::GraphError;
use fss_graph_algorithms::certified::{Budget, CertifiedOutput, CertifiedRun, check_witness};
use fss_graph_algorithms::flow::{self, CutMode, FlowOutput};
use fss_graph_algorithms::min_cost_flow;
use fss_graph_algorithms::stream_capacity::{
    self, CameraDemand, CapacityOutput, CapacityQuery, CapacityStatus, Endpoint, Link, Recorder,
};
use fss_graph_algorithms::weighted::WeightedGraphBuilder;

fn budget() -> Budget {
    Budget::new(
        stream_capacity::MAX_WORK_UNITS,
        stream_capacity::MAX_OUTPUT_ENTRIES,
    )
}

fn link(id: &str, from: &str, to: &str, capacity: u64, unit_cost: u64) -> Link {
    Link {
        id: id.into(),
        from: from.into(),
        to: to.into(),
        capacity,
        unit_cost,
    }
}

fn camera(sensor: &str, node: &str, requested: u64) -> CameraDemand {
    CameraDemand {
        sensor: sensor.into(),
        node: node.into(),
        requested,
    }
}

fn recorder(id: &str, node: &str, capacity: u64) -> Recorder {
    Recorder {
        id: id.into(),
        node: node.into(),
        capacity,
    }
}

fn query() -> CapacityQuery {
    CapacityQuery {
        rate_unit: "megabits-per-second".into(),
        cost_unit: "routing-points".into(),
        nodes: vec!["edge".into(), "store".into()],
        links: vec![link("uplink", "edge", "store", 5, 3)],
        cameras: vec![camera("front", "edge", 4), camera("rear", "edge", 4)],
        recorders: vec![recorder("archive", "store", 8)],
        failed_nodes: BTreeSet::new(),
        failed_links: BTreeSet::new(),
    }
}

/// This oracle never creates a residual graph or calls either production flow algorithm.
/// It enumerates the Cartesian product of every physical link's integral carried rate and
/// every endpoint's integral delivered/received rate, retaining only physical-node conservation.
/// Thus it also enumerates cycles, parallel links, simultaneous recorders and all camera splits.
fn exhaustive(query: &CapacityQuery) -> (u64, u64) {
    struct Variable {
        from: Option<usize>,
        to: Option<usize>,
        capacity: u64,
        cost: u64,
        is_camera: bool,
    }
    fn visit(
        variables: &[Variable],
        index: usize,
        balance: &mut [i64],
        delivered: u64,
        cost: u64,
        best: &mut (u64, u64),
    ) {
        if index == variables.len() {
            if balance.iter().all(|value| *value == 0)
                && (delivered > best.0 || delivered == best.0 && cost < best.1)
            {
                *best = (delivered, cost);
            }
            return;
        }
        let variable = &variables[index];
        assert!(
            variable.capacity <= 3,
            "oracle enumeration must remain tiny"
        );
        for amount in 0..=variable.capacity {
            if let Some(from) = variable.from {
                balance[from] -= amount as i64;
            }
            if let Some(to) = variable.to {
                balance[to] += amount as i64;
            }
            visit(
                variables,
                index + 1,
                balance,
                delivered + if variable.is_camera { amount } else { 0 },
                cost + amount * variable.cost,
                best,
            );
            if let Some(from) = variable.from {
                balance[from] += amount as i64;
            }
            if let Some(to) = variable.to {
                balance[to] -= amount as i64;
            }
        }
    }
    let positions: BTreeMap<&str, usize> = query
        .nodes
        .iter()
        .enumerate()
        .map(|(index, id)| (id.as_str(), index))
        .collect();
    let live = |node: &str| !query.failed_nodes.contains(node);
    let mut variables = Vec::new();
    for item in &query.links {
        let available =
            live(&item.from) && live(&item.to) && !query.failed_links.contains(&item.id);
        variables.push(Variable {
            from: Some(positions[item.from.as_str()]),
            to: Some(positions[item.to.as_str()]),
            capacity: if available { item.capacity } else { 0 },
            cost: item.unit_cost,
            is_camera: false,
        });
    }
    for item in &query.cameras {
        variables.push(Variable {
            from: None,
            to: Some(positions[item.node.as_str()]),
            capacity: if live(&item.node) { item.requested } else { 0 },
            cost: 0,
            is_camera: true,
        });
    }
    for item in &query.recorders {
        variables.push(Variable {
            from: Some(positions[item.node.as_str()]),
            to: None,
            capacity: if live(&item.node) { item.capacity } else { 0 },
            cost: 0,
            is_camera: false,
        });
    }
    let mut best = (0, 0);
    visit(
        &variables,
        0,
        &mut vec![0; query.nodes.len()],
        0,
        0,
        &mut best,
    );
    best
}

fn check_accounting(query: &CapacityQuery, run: &CertifiedRun<CapacityOutput>) -> TestResult {
    let output = &run.output;
    assert_eq!(
        output.requested,
        query.cameras.iter().map(|item| item.requested).sum::<u64>()
    );
    assert_eq!(output.shortfall, output.requested - output.delivered);
    assert_eq!(
        output.status == CapacityStatus::FullyRouted,
        output.shortfall == 0
    );
    assert_eq!(output.cameras.len(), query.cameras.len());
    assert_eq!(output.links.len(), query.links.len());
    assert_eq!(output.recorders.len(), query.recorders.len());
    assert_eq!(output.nodes.len(), query.nodes.len());
    assert_eq!(
        output.failed_nodes,
        query.failed_nodes.iter().cloned().collect::<Vec<_>>()
    );
    assert_eq!(
        output.failed_links,
        query.failed_links.iter().cloned().collect::<Vec<_>>()
    );
    assert_eq!(output.rate_unit, query.rate_unit);
    assert_eq!(output.cost_unit, query.cost_unit);
    let mut balance: BTreeMap<&str, i128> = query.nodes.iter().map(|id| (id.as_str(), 0)).collect();
    for item in &output.cameras {
        assert!(item.delivered <= item.requested);
        assert_eq!(item.shortfall, item.requested - item.delivered);
        assert_eq!(
            item.attachment_failed,
            query.failed_nodes.contains(&item.node)
        );
        if item.attachment_failed {
            assert_eq!(item.delivered, 0);
        }
        *balance
            .get_mut(item.node.as_str())
            .ok_or("missing declared camera attachment")? += i128::from(item.delivered);
    }
    let mut recomputed_cost = 0_u128;
    for item in &output.links {
        let failed = query.failed_links.contains(&item.id);
        let from_failed = query.failed_nodes.contains(&item.from);
        let to_failed = query.failed_nodes.contains(&item.to);
        assert_eq!(
            (item.failed, item.from_failed, item.to_failed),
            (failed, from_failed, to_failed)
        );
        let effective = if failed || from_failed || to_failed {
            0
        } else {
            item.capacity
        };
        assert_eq!(item.effective_capacity(), effective);
        assert!(item.flow <= effective);
        *balance
            .get_mut(item.from.as_str())
            .ok_or("missing declared link source")? -= i128::from(item.flow);
        *balance
            .get_mut(item.to.as_str())
            .ok_or("missing declared link destination")? += i128::from(item.flow);
        recomputed_cost += u128::from(item.flow) * u128::from(item.unit_cost);
    }
    for item in &output.recorders {
        assert!(item.received <= item.capacity);
        assert_eq!(
            item.attachment_failed,
            query.failed_nodes.contains(&item.node)
        );
        if item.attachment_failed {
            assert_eq!(item.received, 0);
        }
        *balance
            .get_mut(item.node.as_str())
            .ok_or("missing declared recorder attachment")? -= i128::from(item.received);
    }
    assert!(
        balance.values().all(|value| *value == 0),
        "physical conservation: {balance:?}"
    );
    assert_eq!(recomputed_cost, u128::from(output.total_cost));
    assert_eq!(
        output
            .cameras
            .iter()
            .map(|item| item.delivered)
            .sum::<u64>(),
        output.delivered
    );
    assert_eq!(
        output
            .recorders
            .iter()
            .map(|item| item.received)
            .sum::<u64>(),
        output.delivered
    );
    let source_side: BTreeSet<_> = output.source_side.iter().cloned().collect();
    assert_eq!(source_side.len(), output.source_side.len());
    assert!(source_side.contains(&Endpoint::Source));
    assert!(!source_side.contains(&Endpoint::Sink));
    assert_eq!(
        output.cut.iter().map(|arc| arc.capacity).sum::<u64>(),
        output.delivered
    );
    let final_flows: BTreeMap<_, _> = output
        .minimum_cost
        .output
        .flows
        .iter()
        .map(|(a, b, amount, _)| ((a.as_str(), b.as_str()), *amount))
        .collect();
    for arc in &output.cut {
        assert!(source_side.contains(&arc.from));
        assert!(!source_side.contains(&arc.to));
        assert_eq!(arc.flow, arc.capacity);
        assert_eq!(
            arc.flow,
            final_flows
                .get(&(
                    arc.from.projection_id().as_str(),
                    arc.to.projection_id().as_str()
                ))
                .copied()
                .unwrap_or(0)
        );
    }
    assert_eq!(run.output_entries, output.entries());
    assert_eq!(run.operations, run.counters.values().sum());
    assert_eq!(
        run.counters["max_flow_operations"],
        output.maximum_flow.operations
    );
    assert_eq!(
        run.counters["min_cost_flow_operations"],
        output.minimum_cost.operations
    );
    Ok(())
}

#[test]
fn shared_bottleneck_preserves_every_camera_demand_and_certifies_shortfall() -> TestResult {
    let query = query();
    let run = stream_capacity::analyze(&query, budget())?;
    assert_eq!(
        (
            run.output.requested,
            run.output.delivered,
            run.output.shortfall,
            run.output.total_cost
        ),
        (8, 5, 3, 15)
    );
    assert_eq!(run.output.status.as_str(), "capacity_shortfall");
    assert_eq!(run.output.links[0].flow, 5);
    assert_eq!(run.output.recorders[0].received, 5);
    check_accounting(&query, &run)?;
    Ok(())
}

#[test]
fn cheapest_routing_splits_across_named_parallel_links_and_recorder_limits() -> TestResult {
    let mut query = query();
    query.links = vec![
        link("expensive", "edge", "store", 8, 9),
        link("cheap", "edge", "store", 3, 1),
    ];
    query.recorders = vec![
        recorder("first", "store", 3),
        recorder("second", "store", 3),
    ];
    let run = stream_capacity::analyze(&query, budget())?;
    assert_eq!(
        (
            run.output.delivered,
            run.output.total_cost,
            run.output.shortfall
        ),
        (6, 30, 2)
    );
    assert_eq!(
        run.output
            .links
            .iter()
            .map(|item| (item.id.as_str(), item.flow))
            .collect::<Vec<_>>(),
        [("cheap", 3), ("expensive", 3)]
    );
    assert!(run.output.recorders.iter().all(|item| item.received == 3));
    check_accounting(&query, &run)?;
    query.failed_links.insert("cheap".into());
    let failed = stream_capacity::analyze(&query, budget())?;
    assert_eq!((failed.output.delivered, failed.output.total_cost), (6, 54));
    assert_eq!(failed.output.links[0].capacity, 3);
    assert_eq!(failed.output.links[0].flow, 0);
    check_accounting(&query, &failed)?;
    Ok(())
}

#[test]
fn backup_route_and_recorder_take_over_after_failures() -> TestResult {
    let mut query = query();
    query.nodes.push("backup".into());
    query.cameras = vec![camera("camera", "edge", 4)];
    query.links = vec![
        link("primary", "edge", "store", 4, 1),
        link("fallback", "edge", "backup", 3, 4),
    ];
    query.recorders = vec![
        recorder("primary", "store", 4),
        recorder("backup", "backup", 3),
    ];
    let baseline = stream_capacity::analyze(&query, budget())?;
    assert_eq!(
        (baseline.output.delivered, baseline.output.total_cost),
        (4, 4)
    );
    query.failed_nodes.insert("store".into());
    let failure = stream_capacity::analyze(&query, budget())?;
    assert_eq!(
        (
            failure.output.requested,
            failure.output.delivered,
            failure.output.shortfall,
            failure.output.total_cost
        ),
        (4, 3, 1, 12)
    );
    assert!(
        failure
            .output
            .recorders
            .iter()
            .any(|item| item.id == "primary" && item.attachment_failed && item.received == 0)
    );
    assert!(
        failure
            .output
            .links
            .iter()
            .any(|item| item.id == "primary" && item.to_failed && item.flow == 0)
    );
    check_accounting(&query, &failure)?;
    query.failed_nodes.insert("edge".into());
    let isolated = stream_capacity::analyze(&query, budget())?;
    assert_eq!(
        (
            isolated.output.requested,
            isolated.output.delivered,
            isolated.output.shortfall
        ),
        (4, 0, 4)
    );
    assert!(isolated.output.cameras[0].attachment_failed);
    assert!(!isolated.output.cut.is_empty());
    assert!(isolated.output.cut.iter().all(|arc| arc.capacity == 0));
    check_accounting(&query, &isolated)?;
    Ok(())
}

#[test]
fn local_recording_needs_no_network_links_and_retains_isolated_demands() -> TestResult {
    let mut query = query();
    query.links.clear();
    query.recorders = vec![recorder("local", "edge", 3)];
    query.cameras.push(camera("isolated", "store", 2));
    let run = stream_capacity::analyze(&query, budget())?;
    assert_eq!(
        (
            run.output.requested,
            run.output.delivered,
            run.output.total_cost
        ),
        (10, 3, 0)
    );
    let isolated = run
        .output
        .cameras
        .iter()
        .find(|item| item.sensor == "isolated")
        .ok_or("missing retained isolated sensor")?;
    assert_eq!(
        (isolated.requested, isolated.delivered, isolated.shortfall),
        (2, 0, 2)
    );
    check_accounting(&query, &run)?;
    Ok(())
}

#[test]
fn endpoint_types_disambiguate_identical_external_names() -> TestResult {
    let query = CapacityQuery {
        rate_unit: "units".into(),
        cost_unit: "points".into(),
        nodes: vec!["same".into(), "0:source".into()],
        links: vec![link("same", "same", "0:source", 2, 1)],
        cameras: vec![camera("same", "same", 2)],
        recorders: vec![recorder("same", "0:source", 2)],
        failed_nodes: BTreeSet::new(),
        failed_links: BTreeSet::new(),
    };
    let endpoints = [
        Endpoint::Source,
        Endpoint::Node("same".into()),
        Endpoint::Link("same".into()),
        Endpoint::Camera("same".into()),
        Endpoint::Recorder("same".into()),
        Endpoint::Sink,
    ];
    assert_eq!(
        endpoints
            .iter()
            .map(Endpoint::projection_id)
            .collect::<BTreeSet<_>>()
            .len(),
        endpoints.len()
    );
    let run = stream_capacity::analyze(&query, budget())?;
    assert_eq!((run.output.delivered, run.output.total_cost), (2, 2));
    assert_eq!(run.output.status.as_str(), "fully_routed");
    check_accounting(&query, &run)?;
    Ok(())
}

#[test]
fn final_cut_uses_the_cost_optimal_flow_even_when_initial_maximum_flow_differs() -> TestResult {
    let mut query = query();
    query.cameras = vec![camera("camera", "edge", 2)];
    query.links = vec![
        link("a-costly", "edge", "store", 2, 10),
        link("z-cheap", "edge", "store", 2, 1),
    ];
    let run = stream_capacity::analyze(&query, budget())?;
    let FlowOutput::Arcs(maximum) = &run.output.maximum_flow.output else {
        return Err("expected arc cut".into());
    };
    assert!(
        maximum
            .flows
            .iter()
            .any(|(_, to, amount)| to == "2/link/a-costly" && *amount == 2)
    );
    assert_eq!(run.output.links[0].flow, 0);
    assert_eq!(run.output.links[1].flow, 2);
    assert_eq!(run.output.total_cost, 2);
    assert_eq!(run.output.cut.len(), 1);
    assert_eq!(run.output.cut[0].from, Endpoint::Source);
    // A demand-limited cut is intentionally not a statement about unused physical capacity.
    check_accounting(&query, &run)?;
    Ok(())
}

fn tiny_query(seed: u64) -> CapacityQuery {
    let mut rng = Rng(seed ^ 0xcaf0_5700_d00d_0001);
    let nodes = ["n0", "n1", "n2"];
    let links = (0..rng.below(7))
        .map(|index| {
            let from = rng.below(3);
            let to = (from + 1 + rng.below(2)) % 3;
            link(
                &format!("link-{index}"),
                nodes[from],
                nodes[to],
                1 + rng.below(2) as u64,
                rng.below(4) as u64,
            )
        })
        .collect();
    let cameras = (0..2)
        .map(|index| {
            camera(
                &format!("camera-{index}"),
                nodes[rng.below(3)],
                1 + rng.below(2) as u64,
            )
        })
        .collect();
    let recorders = (0..2)
        .map(|index| {
            recorder(
                &format!("recorder-{index}"),
                nodes[rng.below(3)],
                1 + rng.below(2) as u64,
            )
        })
        .collect();
    let mut query = CapacityQuery {
        rate_unit: "units".into(),
        cost_unit: "points".into(),
        nodes: nodes.into_iter().map(str::to_owned).collect(),
        links,
        cameras,
        recorders,
        failed_nodes: BTreeSet::new(),
        failed_links: BTreeSet::new(),
    };
    if seed.is_multiple_of(4) {
        query.failed_nodes.insert(nodes[rng.below(3)].into());
    }
    if seed.is_multiple_of(5) && !query.links.is_empty() {
        query
            .failed_links
            .insert(query.links[rng.below(query.links.len())].id.clone());
    }
    query
}

#[test]
fn seeded_complete_integral_flow_enumeration_proves_both_objectives() -> TestResult {
    let mut shortages = 0;
    let mut complete = 0;
    let mut positive_cost = 0;
    for seed in 0..256 {
        let query = tiny_query(seed);
        let expected = exhaustive(&query);
        let run = stream_capacity::analyze(&query, budget())?;
        assert_eq!(
            (run.output.delivered, run.output.total_cost),
            expected,
            "seed {seed}: {query:?}"
        );
        shortages += usize::from(run.output.shortfall != 0);
        complete += usize::from(run.output.shortfall == 0);
        positive_cost += usize::from(run.output.total_cost != 0);
        check_accounting(&query, &run)?;
        let mut permuted = query.clone();
        let mut rng = Rng(seed ^ 0x9876_5432);
        rng.shuffle(&mut permuted.nodes);
        rng.shuffle(&mut permuted.links);
        rng.shuffle(&mut permuted.cameras);
        rng.shuffle(&mut permuted.recorders);
        assert_eq!(
            stream_capacity::analyze(&permuted, budget())?,
            run,
            "permutation seed {seed}"
        );
    }
    assert!(
        shortages > 100 && complete > 20 && positive_cost > 10,
        "exercise outcomes: shortages={shortages}, complete={complete}, positive_cost={positive_cost}"
    );
    Ok(())
}

#[test]
fn additional_failures_never_increase_delivery_and_match_the_oracle() -> TestResult {
    for seed in 0..64 {
        let mut query = tiny_query(seed);
        query.failed_nodes.clear();
        query.failed_links.clear();
        let baseline = stream_capacity::analyze(&query, budget())?;
        for node in query.nodes.clone() {
            let mut failed = query.clone();
            failed.failed_nodes.insert(node);
            let run = stream_capacity::analyze(&failed, budget())?;
            assert!(run.output.delivered <= baseline.output.delivered);
            assert_eq!(run.output.requested, baseline.output.requested);
            assert_eq!(
                (run.output.delivered, run.output.total_cost),
                exhaustive(&failed)
            );
            check_accounting(&failed, &run)?;
        }
        for link in query.links.clone() {
            let mut failed = query.clone();
            failed.failed_links.insert(link.id);
            let run = stream_capacity::analyze(&failed, budget())?;
            assert!(run.output.delivered <= baseline.output.delivered);
            assert_eq!(
                (run.output.delivered, run.output.total_cost),
                exhaustive(&failed)
            );
        }
    }
    Ok(())
}

#[test]
fn zero_cost_cycles_and_antiparallel_physical_links_match_enumeration() -> TestResult {
    let mut query = tiny_query(1);
    query.cameras = vec![camera("camera", "n0", 3)];
    query.recorders = vec![recorder("recorder", "n2", 3)];
    query.links = vec![
        link("a", "n0", "n1", 2, 0),
        link("b", "n1", "n0", 2, 0),
        link("c", "n1", "n2", 1, 0),
        link("d", "n0", "n2", 2, 2),
        link("e", "n2", "n0", 2, 0),
    ];
    query.failed_nodes.clear();
    query.failed_links.clear();
    let run = stream_capacity::analyze(&query, budget())?;
    assert_eq!((run.output.delivered, run.output.total_cost), (3, 4));
    assert_eq!(
        (run.output.delivered, run.output.total_cost),
        exhaustive(&query)
    );
    check_accounting(&query, &run)?;
    Ok(())
}

#[test]
fn every_declaration_including_failed_unused_topology_and_units_binds_the_input() -> TestResult {
    let mut query = query();
    query.nodes.push("unused".into());
    query.links.push(link("unused", "store", "unused", 1, 0));
    query.failed_links.insert("unused".into());
    let run = stream_capacity::analyze(&query, budget())?;
    let mut variants = Vec::new();
    let mut changed = query.clone();
    changed.links[1].capacity = 2;
    variants.push(changed);
    let mut changed = query.clone();
    changed.links[1].unit_cost = 17;
    variants.push(changed);
    let mut changed = query.clone();
    changed.rate_unit = "bytes-per-second".into();
    variants.push(changed);
    let mut changed = query.clone();
    changed.cost_unit = "price".into();
    variants.push(changed);
    let mut changed = query.clone();
    changed.nodes.push("another-unused".into());
    variants.push(changed);
    let mut changed = query.clone();
    changed.cameras[0].requested += 1;
    variants.push(changed);
    let mut changed = query.clone();
    changed.failed_nodes.insert("unused".into());
    variants.push(changed);
    for changed in variants {
        assert_ne!(
            stream_capacity::analyze(&changed, budget())?.input_digest,
            run.input_digest
        );
    }
    let mut encoded = CanonicalEncoder::new();
    encoded.text(stream_capacity::OUTPUT_DOMAIN);
    run.output.encode(&mut encoded);
    assert_eq!(
        run.output_digest,
        ContentDigest::sha256(&encoded.finish_checked()?)
    );
    let mut tampered = run.output.clone();
    tampered.minimum_cost.operations += 1;
    let mut encoded = CanonicalEncoder::new();
    encoded.text(stream_capacity::OUTPUT_DOMAIN);
    tampered.encode(&mut encoded);
    assert_ne!(
        run.output_digest,
        ContentDigest::sha256(&encoded.finish_checked()?)
    );
    Ok(())
}

#[test]
fn three_nested_witnesses_have_registered_identities_and_recheckable_bounds() -> TestResult {
    let run = stream_capacity::analyze(&query(), budget())?;
    let anchor = LedgerAnchor::genesis("capacity-test");
    let top = run.witness("projection:retained-capacity:test", anchor.clone())?;
    check_witness(
        &top,
        &stream_capacity::IDENTITY,
        &stream_capacity::bound(run.node_count, run.edge_count, run.output.requested),
    )?;
    let maximum = &run.output.maximum_flow;
    let witness = maximum.witness("projection:retained-capacity:test:maxflow", anchor.clone())?;
    check_witness(
        &witness,
        &flow::IDENTITY,
        &flow::bound(maximum.node_count, maximum.edge_count),
    )?;
    let minimum = &run.output.minimum_cost;
    let witness = minimum.witness("projection:retained-capacity:test:mincost", anchor)?;
    check_witness(
        &witness,
        &min_cost_flow::IDENTITY,
        &min_cost_flow::bound(
            minimum.node_count,
            minimum.edge_count,
            minimum.output.requested,
        ),
    )?;
    assert!(
        check_witness(
            &top,
            &min_cost_flow::IDENTITY,
            &min_cost_flow::bound(run.node_count, run.edge_count, run.output.requested)
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn aggregate_work_and_complete_output_allowances_are_exact() -> TestResult {
    let query = query();
    let run = stream_capacity::analyze(&query, budget())?;
    assert!(
        run.operations > run.output.maximum_flow.operations + run.output.minimum_cost.operations
    );
    assert!(
        run.output_entries
            > run.output.maximum_flow.output_entries + run.output.minimum_cost.output_entries
    );
    assert_eq!(
        stream_capacity::analyze(&query, Budget::new(run.operations, run.output_entries))?,
        run
    );
    for limits in [
        Budget::new(run.operations - 1, run.output_entries),
        Budget::new(run.operations, run.output_entries - 1),
        Budget::new(
            run.output.maximum_flow.operations + run.output.minimum_cost.operations,
            run.output_entries,
        ),
        Budget::new(
            run.operations,
            run.output.maximum_flow.output_entries + run.output.minimum_cost.output_entries,
        ),
        Budget::new(0, run.output_entries),
        Budget::new(run.operations, 0),
    ] {
        assert!(
            matches!(
                stream_capacity::analyze(&query, limits),
                Err(GraphError::BudgetExhausted { .. })
            ),
            "{limits:?}"
        );
    }
    for limits in [
        Budget::new(
            stream_capacity::MAX_WORK_UNITS + 1,
            stream_capacity::MAX_OUTPUT_ENTRIES,
        ),
        Budget::new(
            stream_capacity::MAX_WORK_UNITS,
            stream_capacity::MAX_OUTPUT_ENTRIES + 1,
        ),
    ] {
        assert!(matches!(
            stream_capacity::analyze(&query, limits),
            Err(GraphError::PreconditionFailed(_))
        ));
    }
    Ok(())
}

#[test]
fn cancellation_at_every_cooperative_checkpoint_returns_no_partial_answer() -> TestResult {
    let query = query();
    let probes = Cell::new(0_usize);
    let run = stream_capacity::analyze_with_cancel(&query, budget(), &|| {
        probes.set(probes.get() + 1);
        false
    })?;
    assert_eq!(run, stream_capacity::analyze(&query, budget())?);
    let total = probes.get();
    assert!(total > 100);
    for stop_at in 1..=total {
        probes.set(0);
        let result = stream_capacity::analyze_with_cancel(&query, budget(), &|| {
            probes.set(probes.get() + 1);
            probes.get() == stop_at
        });
        assert_eq!(
            result.err(),
            Some(GraphError::Cancelled),
            "checkpoint {stop_at} of {total}"
        );
        assert_eq!(probes.get(), stop_at);
    }
    assert_eq!(GraphError::Cancelled.stable_id(), "ERR-GRAPH-CANCELLED-001");
    Ok(())
}

#[test]
fn malformed_or_ambiguous_declarations_are_refused() {
    let query = query();
    let mut cases = Vec::new();
    let mut bad = query.clone();
    bad.nodes.push(bad.nodes[0].clone());
    cases.push(bad);
    let mut bad = query.clone();
    bad.cameras.push(bad.cameras[0].clone());
    cases.push(bad);
    let mut bad = query.clone();
    bad.links.push(bad.links[0].clone());
    cases.push(bad);
    let mut bad = query.clone();
    bad.recorders.push(bad.recorders[0].clone());
    cases.push(bad);
    let mut bad = query.clone();
    bad.links[0].from = "unknown".into();
    cases.push(bad);
    let mut bad = query.clone();
    bad.cameras[0].node = "unknown".into();
    cases.push(bad);
    let mut bad = query.clone();
    bad.recorders[0].node = "unknown".into();
    cases.push(bad);
    let mut bad = query.clone();
    bad.failed_nodes.insert("unknown".into());
    cases.push(bad);
    let mut bad = query.clone();
    bad.failed_links.insert("unknown".into());
    cases.push(bad);
    let mut bad = query.clone();
    bad.links[0].capacity = 0;
    cases.push(bad);
    let mut bad = query.clone();
    bad.cameras[0].requested = 0;
    cases.push(bad);
    let mut bad = query.clone();
    bad.recorders[0].capacity = 0;
    cases.push(bad);
    let mut bad = query.clone();
    bad.links[0].to = bad.links[0].from.clone();
    cases.push(bad);
    let mut bad = query.clone();
    bad.rate_unit = "".into();
    cases.push(bad);
    let mut bad = query.clone();
    bad.cost_unit = "bad unit".into();
    cases.push(bad);
    let mut bad = query.clone();
    bad.cameras[0].sensor = "bad\nidentity".into();
    cases.push(bad);
    let mut bad = query.clone();
    bad.cameras[0].sensor = "3/camera/other".into();
    cases.push(bad);
    let mut bad = query.clone();
    bad.recorders[0].id = "unicode-\u{03c0}".into();
    cases.push(bad);
    let mut bad = query.clone();
    bad.nodes[0] = "a".repeat(stream_capacity::MAX_ID_BYTES + 1);
    cases.push(bad);
    let mut bad = query.clone();
    bad.rate_unit = "a".repeat(stream_capacity::MAX_UNIT_BYTES + 1);
    cases.push(bad);
    let mut bad = query.clone();
    bad.nodes.clear();
    cases.push(bad);
    let mut bad = query.clone();
    bad.cameras.clear();
    cases.push(bad);
    let mut bad = query.clone();
    bad.recorders.clear();
    cases.push(bad);
    let mut bad = query.clone();
    bad.nodes = vec!["a".into(); stream_capacity::MAX_NODES + 1];
    cases.push(bad);
    let mut bad = query.clone();
    bad.links = vec![bad.links[0].clone(); stream_capacity::MAX_LINKS + 1];
    cases.push(bad);
    let mut bad = query.clone();
    bad.cameras = vec![bad.cameras[0].clone(); stream_capacity::MAX_CAMERAS + 1];
    cases.push(bad);
    let mut bad = query.clone();
    bad.recorders = vec![bad.recorders[0].clone(); stream_capacity::MAX_RECORDERS + 1];
    cases.push(bad);
    for (index, bad) in cases.into_iter().enumerate() {
        assert!(
            matches!(
                stream_capacity::analyze(&bad, budget()),
                Err(GraphError::PreconditionFailed(_)
                    | GraphError::UnknownNode(_)
                    | GraphError::SelfLoop(_)
                    | GraphError::TooLarge)
            ),
            "malformed case {index}"
        );
    }
}

#[test]
fn exact_identifier_and_unit_limits_are_admitted() -> TestResult {
    let mut query = query();
    query.rate_unit = "r".repeat(stream_capacity::MAX_UNIT_BYTES);
    query.cost_unit = "c".repeat(stream_capacity::MAX_UNIT_BYTES);
    query.cameras[0].sensor = "s".repeat(stream_capacity::MAX_ID_BYTES);
    query.recorders[0].id = "z".repeat(stream_capacity::MAX_ID_BYTES);
    query.links[0].id = "l".repeat(stream_capacity::MAX_ID_BYTES);
    let run = stream_capacity::analyze(&query, budget())?;
    check_accounting(&query, &run)?;
    Ok(())
}

#[test]
fn checked_numeric_limits_accept_large_zero_cost_flow_and_refuse_overflow() -> TestResult {
    let mut query = query();
    query.cameras = vec![camera("one", "edge", u64::MAX)];
    query.links[0].capacity = u64::MAX;
    query.links[0].unit_cost = 0;
    query.recorders[0].capacity = u64::MAX;
    let run = stream_capacity::analyze(&query, budget())?;
    assert_eq!(
        (
            run.output.requested,
            run.output.delivered,
            run.output.shortfall,
            run.output.total_cost
        ),
        (u64::MAX, u64::MAX, 0, 0)
    );
    check_accounting(&query, &run)?;
    query.cameras.push(camera("two", "edge", 1));
    assert!(matches!(
        stream_capacity::analyze(&query, budget()),
        Err(GraphError::ArithmeticOverflow(_))
    ));
    query.cameras.pop();
    query.links[0].unit_cost = u64::MAX;
    // The product does not even fit i128: this must refuse rather than panic or wrap.
    assert!(matches!(
        stream_capacity::analyze(&query, budget()),
        Err(GraphError::ArithmeticOverflow(_))
    ));
    query.cameras[0].requested = 2;
    assert!(matches!(
        stream_capacity::analyze(&query, budget()),
        Err(GraphError::ArithmeticOverflow(_))
    ));
    query.cameras[0].requested = 1;
    let run = stream_capacity::analyze(&query, budget())?;
    assert_eq!(run.output.total_cost, u64::MAX);
    check_accounting(&query, &run)?;
    Ok(())
}

#[test]
fn additive_solver_cancellation_preserves_successful_legacy_runs() -> TestResult {
    let mut costs = WeightedGraphBuilder::directed("cost");
    let mut capacities = WeightedGraphBuilder::directed("rate");
    for id in ["s", "a", "b", "t"] {
        costs.add_node(id);
        capacities.add_node(id);
    }
    for (from, to, capacity, cost) in [
        ("s", "a", 3, 4),
        ("a", "t", 2, 1),
        ("s", "b", 2, 0),
        ("b", "t", 2, 2),
        ("a", "b", 1, 0),
    ] {
        costs.add_arc(from, to, cost);
        capacities.add_arc(from, to, capacity);
    }
    let (costs, capacities) = (costs.build()?, capacities.build()?);
    for mode in [CutMode::Arcs, CutMode::Nodes] {
        let old = flow::max_flow_min_cut(&capacities, "s", "t", mode, budget())?;
        let mut count = 0;
        let probes = Cell::new(0);
        let new =
            flow::max_flow_min_cut_with_cancel(&capacities, "s", "t", mode, budget(), &|| {
                probes.set(probes.get() + 1);
                false
            })?;
        assert_eq!(old, new);
        for stop in [1, probes.get() / 2, probes.get()] {
            let progress = Cell::new(0);
            assert_eq!(
                flow::max_flow_min_cut_with_cancel(&capacities, "s", "t", mode, budget(), &|| {
                    progress.set(progress.get() + 1);
                    progress.get() == stop
                })
                .err(),
                Some(GraphError::Cancelled)
            );
            count += 1;
        }
        assert_eq!(count, 3);
    }
    let old = min_cost_flow::min_cost_flow(&costs, &capacities, "s", "t", 5, budget())?;
    let probes = Cell::new(0);
    let new = min_cost_flow::min_cost_flow_with_cancel(
        &costs,
        &capacities,
        "s",
        "t",
        5,
        budget(),
        &|| {
            probes.set(probes.get() + 1);
            false
        },
    )?;
    assert_eq!(old, new);
    for stop in [1, probes.get() / 2, probes.get()] {
        let progress = Cell::new(0);
        assert_eq!(
            min_cost_flow::min_cost_flow_with_cancel(
                &costs,
                &capacities,
                "s",
                "t",
                5,
                budget(),
                &|| {
                    progress.set(progress.get() + 1);
                    progress.get() == stop
                }
            )
            .err(),
            Some(GraphError::Cancelled)
        );
    }
    Ok(())
}

#[test]
fn direct_min_cost_owner_refuses_product_above_i128_without_panicking() -> TestResult {
    let mut costs = WeightedGraphBuilder::directed("cost");
    let mut capacities = WeightedGraphBuilder::directed("rate");
    for id in ["s", "t"] {
        costs.add_node(id);
        capacities.add_node(id);
    }
    costs.add_arc("s", "t", u64::MAX);
    capacities.add_arc("s", "t", u64::MAX);
    let (costs, capacities) = (costs.build()?, capacities.build()?);
    assert!(matches!(
        min_cost_flow::min_cost_flow(&costs, &capacities, "s", "t", u64::MAX, budget()),
        Err(GraphError::ArithmeticOverflow(_))
    ));
    Ok(())
}

//! Brute-force oracles for the weighted and directed registered families.
//!
//! Each oracle implements the registered *definition* independently of the certified run
//! (repeated reachability, removal, subset enumeration, Bellman–Ford relaxation, exhaustive path
//! or matching enumeration) and is meant for small inputs only: certification tests compare the
//! certified answer with these on thousands of seeded graphs. None of them is metered, bounded,
//! or used on a production path.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::dominators::{DominanceDirection, DominanceOutput};
use crate::flow::ArcCutOutput;
use crate::graph::GraphError;
use crate::paths::{DistanceRow, MultiSourceOutput, NearestRow, ShortestPathOutput};
use crate::scc::{Component, SccOutput};
use crate::topo::{ScheduleRow, TopoOutput};
use crate::weighted::{Orientation, WeightedGraph};

/// `(neighbour, arc index)` pairs leaving `node` (both directions when undirected).
fn steps(graph: &WeightedGraph, node: u32, reverse: bool) -> Vec<(u32, u32)> {
    let mut result = Vec::new();
    for (index, arc) in graph.arcs().iter().enumerate() {
        let index = index as u32;
        match graph.orientation() {
            Orientation::Directed => {
                if !reverse && arc.tail == node {
                    result.push((arc.head, index));
                }
                if reverse && arc.head == node {
                    result.push((arc.tail, index));
                }
            }
            Orientation::Undirected => {
                if arc.tail == node {
                    result.push((arc.head, index));
                }
                if arc.head == node {
                    result.push((arc.tail, index));
                }
            }
        }
    }
    result
}

/// Nodes reachable from `start` avoiding `removed`, following arcs forward (or backward).
#[must_use]
pub fn reach(graph: &WeightedGraph, start: u32, removed: Option<u32>, reverse: bool) -> Vec<bool> {
    let n = graph.node_count();
    let mut seen = vec![false; n];
    if Some(start) == removed {
        return seen;
    }
    seen[start as usize] = true;
    let mut queue = VecDeque::from([start]);
    while let Some(u) = queue.pop_front() {
        for (v, _) in steps(graph, u, reverse) {
            if Some(v) != removed && !seen[v as usize] {
                seen[v as usize] = true;
                queue.push_back(v);
            }
        }
    }
    seen
}

/// `ALG-SCC-001` by mutual reachability.
#[must_use]
pub fn scc(graph: &WeightedGraph) -> SccOutput {
    let n = graph.node_count();
    let reach_from: Vec<Vec<bool>> = (0..n as u32)
        .map(|u| reach(graph, u, None, false))
        .collect();
    let mut component_of = vec![usize::MAX; n];
    let mut members: Vec<Vec<u32>> = Vec::new();
    for u in 0..n {
        if component_of[u] != usize::MAX {
            continue;
        }
        let list: Vec<u32> = (0..n)
            .filter(|&v| reach_from[u][v] && reach_from[v][u])
            .map(|v| v as u32)
            .collect();
        for &v in &list {
            component_of[v as usize] = members.len();
        }
        members.push(list);
    }
    let c = members.len();
    let mut arcs: BTreeSet<(usize, usize)> = BTreeSet::new();
    for arc in graph.arcs() {
        let (a, b) = (
            component_of[arc.tail as usize],
            component_of[arc.head as usize],
        );
        if a != b {
            arcs.insert((a, b));
        }
    }
    let mut placed = vec![false; c];
    let mut label = vec![0_u32; c];
    let mut order = Vec::new();
    while order.len() < c {
        let next = (0..c)
            .filter(|&x| !placed[x] && arcs.iter().all(|&(a, b)| b != x || placed[a]))
            .min_by_key(|&x| members[x][0]);
        let Some(next) = next else { break };
        placed[next] = true;
        label[next] = order.len() as u32;
        order.push(next);
    }
    SccOutput {
        components: order
            .iter()
            .enumerate()
            .map(|(position, &x)| Component {
                label: position as u32,
                members: members[x].iter().map(|&v| graph.id(v).to_owned()).collect(),
                cyclic: members[x].len() > 1,
            })
            .collect(),
        condensation_arcs: arcs
            .iter()
            .map(|&(a, b)| (label[a], label[b]))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    }
}

/// `ALG-TOPO-001` by repeated smallest-available selection and `n`-round relaxation.
///
/// # Errors
///
/// [`GraphError::PreconditionFailed`] for a cyclic graph.
pub fn topo(graph: &WeightedGraph) -> Result<TopoOutput, GraphError> {
    let n = graph.node_count();
    let arcs = graph.arcs();
    let mut placed = vec![false; n];
    let mut order: Vec<u32> = Vec::new();
    while order.len() < n {
        let next = (0..n as u32).find(|&v| {
            !placed[v as usize]
                && arcs
                    .iter()
                    .all(|arc| arc.head != v || placed[arc.tail as usize])
        });
        let Some(next) = next else {
            return Err(GraphError::PreconditionFailed("cyclic".to_owned()));
        };
        placed[next as usize] = true;
        order.push(next);
    }
    let duration: Vec<u64> = (0..n as u32).map(|v| graph.node_weight(v)).collect();
    let mut es = vec![0_u64; n];
    let mut level = vec![0_u32; n];
    for _ in 0..n {
        for arc in arcs {
            let (t, h) = (arc.tail as usize, arc.head as usize);
            es[h] = es[h].max(es[t] + duration[t] + arc.weight);
            level[h] = level[h].max(level[t] + 1);
        }
    }
    let ef: Vec<u64> = (0..n).map(|v| es[v] + duration[v]).collect();
    let makespan = ef.iter().copied().max().unwrap_or(0);
    let mut lf = vec![makespan; n];
    for _ in 0..n {
        for arc in arcs {
            let (t, h) = (arc.tail as usize, arc.head as usize);
            lf[t] = lf[t].min(lf[h] - duration[h] - arc.weight);
        }
    }
    let ls: Vec<u64> = (0..n).map(|v| lf[v] - duration[v]).collect();
    let slack: Vec<u64> = (0..n).map(|v| ls[v] - es[v]).collect();
    let tight =
        |t: usize, h: usize, lag: u64| slack[t] == 0 && slack[h] == 0 && ef[t] + lag == es[h];
    let mut critical_path = Vec::new();
    let start = (0..n).find(|&v| {
        es[v] == 0
            && slack[v] == 0
            && !arcs
                .iter()
                .any(|arc| arc.head as usize == v && tight(arc.tail as usize, v, arc.weight))
    });
    if let Some(mut current) = start {
        loop {
            critical_path.push(graph.id(current as u32).to_owned());
            let next = arcs
                .iter()
                .filter(|arc| {
                    arc.tail as usize == current && tight(current, arc.head as usize, arc.weight)
                })
                .map(|arc| arc.head as usize)
                .min();
            match next {
                Some(head) => current = head,
                None => break,
            }
        }
    }
    let depth = level.iter().copied().max().map_or(0, |d| d as usize + 1);
    let mut frontiers = vec![Vec::new(); if n == 0 { 0 } else { depth }];
    for v in 0..n {
        frontiers[level[v] as usize].push(graph.id(v as u32).to_owned());
    }
    Ok(TopoOutput {
        order: order.iter().map(|&v| graph.id(v).to_owned()).collect(),
        frontiers,
        schedule: (0..n)
            .map(|v| ScheduleRow {
                node: graph.id(v as u32).to_owned(),
                duration: duration[v],
                earliest_start: es[v],
                earliest_finish: ef[v],
                latest_start: ls[v],
                latest_finish: lf[v],
                slack: slack[v],
                level: level[v],
            })
            .collect(),
        makespan,
        critical_path,
    })
}

/// `ALG-DOM-001` by single-node removal.
#[must_use]
pub fn dominators(
    graph: &WeightedGraph,
    root: u32,
    direction: DominanceDirection,
) -> DominanceOutput {
    let n = graph.node_count();
    let reverse = direction == DominanceDirection::PostDominators;
    let reachable = reach(graph, root, None, reverse);
    let mut dom: Vec<BTreeSet<u32>> = vec![BTreeSet::new(); n];
    for d in 0..n as u32 {
        let without = reach(graph, root, Some(d), reverse);
        for v in 0..n {
            if reachable[v] && (v == d as usize || !without[v]) {
                dom[v].insert(d);
            }
        }
    }
    let mut immediate = Vec::new();
    let mut unreachable = Vec::new();
    let mut dominance = Vec::new();
    for v in 0..n as u32 {
        if !reachable[v as usize] {
            unreachable.push(graph.id(v).to_owned());
            continue;
        }
        if v != root {
            let idom = dom[v as usize]
                .iter()
                .copied()
                .filter(|&d| d != v)
                .max_by_key(|&d| dom[d as usize].len());
            if let Some(idom) = idom {
                immediate.push((graph.id(v).to_owned(), graph.id(idom).to_owned()));
            }
        }
        let count = (0..n)
            .filter(|&w| w != v as usize && dom[w].contains(&v))
            .count() as u64;
        if count > 0 {
            dominance.push((graph.id(v).to_owned(), count));
        }
    }
    DominanceOutput {
        direction,
        root: graph.id(root).to_owned(),
        immediate_dominators: immediate,
        unreachable,
        dominance,
    }
}

type Key = (u64, u64);

fn bellman_ford(graph: &WeightedGraph, source: u32) -> Vec<Option<Key>> {
    let n = graph.node_count();
    let mut best: Vec<Option<Key>> = vec![None; n];
    best[source as usize] = Some((0, 0));
    for _ in 0..n {
        for u in 0..n as u32 {
            let Some((d, h)) = best[u as usize] else {
                continue;
            };
            for (v, arc) in steps(graph, u, false) {
                let candidate = (d + graph.arc(arc).weight, h + 1);
                if best[v as usize].is_none_or(|current| candidate < current) {
                    best[v as usize] = Some(candidate);
                }
            }
        }
    }
    best
}

/// `ALG-SP-001` by Bellman–Ford over `(distance, hops)`.
#[must_use]
pub fn shortest_paths(
    graph: &WeightedGraph,
    source: u32,
    target: Option<u32>,
) -> ShortestPathOutput {
    let n = graph.node_count();
    let best = bellman_ford(graph, source);
    let mut parent = vec![None; n];
    for v in 0..n as u32 {
        let Some((d, h)) = best[v as usize] else {
            continue;
        };
        if v == source {
            continue;
        }
        parent[v as usize] = steps(graph, v, true)
            .into_iter()
            .filter(|&(u, arc)| {
                best[u as usize]
                    .is_some_and(|(du, hu)| du + graph.arc(arc).weight == d && hu + 1 == h)
            })
            .min_by_key(|&(_, arc)| arc)
            .map(|(u, _)| u);
    }
    let reachable = (0..n as u32)
        .filter_map(|v| {
            best[v as usize].map(|(distance, hops)| DistanceRow {
                node: graph.id(v).to_owned(),
                distance,
                hops,
                parent: parent[v as usize].map(|u: u32| graph.id(u).to_owned()),
            })
        })
        .collect();
    let unreachable = (0..n as u32)
        .filter(|&v| best[v as usize].is_none())
        .map(|v| graph.id(v).to_owned())
        .collect();
    let target = target.map(|goal| {
        let path = best[goal as usize].map(|_| {
            let mut path = vec![graph.id(goal).to_owned()];
            let mut current = goal;
            while let Some(u) = parent[current as usize] {
                path.push(graph.id(u).to_owned());
                current = u;
            }
            path.reverse();
            path
        });
        (graph.id(goal).to_owned(), path)
    });
    ShortestPathOutput {
        source: graph.id(source).to_owned(),
        reachable,
        unreachable,
        target,
    }
}

/// `ALG-MSD-001` as the minimum over per-source Bellman–Ford answers.
#[must_use]
pub fn multi_source(graph: &WeightedGraph, sources: &[u32]) -> MultiSourceOutput {
    let n = graph.node_count();
    let mut sorted = sources.to_vec();
    sorted.sort_unstable();
    let mut best: Vec<Option<(u64, u32, u64)>> = vec![None; n];
    for (rank, &source) in sorted.iter().enumerate() {
        for (v, key) in bellman_ford(graph, source).into_iter().enumerate() {
            if let Some((d, h)) = key {
                let candidate = (d, rank as u32, h);
                if best[v].is_none_or(|current| candidate < current) {
                    best[v] = Some(candidate);
                }
            }
        }
    }
    MultiSourceOutput {
        sources: sorted.iter().map(|&s| graph.id(s).to_owned()).collect(),
        reachable: (0..n)
            .filter_map(|v| {
                best[v].map(|(distance, rank, hops)| NearestRow {
                    node: graph.id(v as u32).to_owned(),
                    source: graph.id(sorted[rank as usize]).to_owned(),
                    distance,
                    hops,
                })
            })
            .collect(),
        unreachable: (0..n)
            .filter(|&v| best[v].is_none())
            .map(|v| graph.id(v as u32).to_owned())
            .collect(),
    }
}

/// `ALG-FLOW-001` (arcs) by enumerating every source-side set: the minimum cut value and the
/// inclusion-minimal minimum source side (the intersection of all minimum source sides).
/// Flows are not unique and are left empty; certification checks them separately.
#[must_use]
pub fn min_arc_cut(graph: &WeightedGraph, s: u32, t: u32) -> ArcCutOutput {
    let n = graph.node_count();
    let mut best: Option<u64> = None;
    let mut intersection: u64 = u64::MAX;
    for mask in 0_u64..(1 << n) {
        if mask & (1 << s) == 0 || mask & (1 << t) != 0 {
            continue;
        }
        let inside = |v: u32| mask & (1 << v) != 0;
        let capacity: u64 = graph
            .arcs()
            .iter()
            .filter(|arc| match graph.orientation() {
                Orientation::Directed => inside(arc.tail) && !inside(arc.head),
                Orientation::Undirected => inside(arc.tail) != inside(arc.head),
            })
            .map(|arc| arc.weight)
            .sum();
        match best {
            Some(value) if capacity > value => {}
            Some(value) if capacity == value => intersection &= mask,
            _ => {
                best = Some(capacity);
                intersection = mask;
            }
        }
    }
    let value = best.unwrap_or(0);
    let inside = |v: u32| intersection & (1 << v) != 0;
    ArcCutOutput {
        source: graph.id(s).to_owned(),
        sink: graph.id(t).to_owned(),
        value,
        flows: Vec::new(),
        source_side: (0..n as u32)
            .filter(|&v| inside(v))
            .map(|v| graph.id(v).to_owned())
            .collect(),
        cut: graph
            .arcs()
            .iter()
            .filter(|arc| match graph.orientation() {
                Orientation::Directed => inside(arc.tail) && !inside(arc.head),
                Orientation::Undirected => inside(arc.tail) != inside(arc.head),
            })
            .map(|arc| {
                (
                    graph.id(arc.tail).to_owned(),
                    graph.id(arc.head).to_owned(),
                    arc.weight,
                )
            })
            .collect(),
    }
}

/// Whether `t` stays reachable from `s` once `removed` nodes fail.
#[must_use]
pub fn connected_without(graph: &WeightedGraph, s: u32, t: u32, removed: &BTreeSet<u32>) -> bool {
    let n = graph.node_count();
    let mut seen = vec![false; n];
    seen[s as usize] = true;
    let mut queue = VecDeque::from([s]);
    while let Some(u) = queue.pop_front() {
        for (v, _) in steps(graph, u, false) {
            if !removed.contains(&v) && !seen[v as usize] {
                seen[v as usize] = true;
                queue.push_back(v);
            }
        }
    }
    seen[t as usize]
}

/// `ALG-FLOW-001` (nodes): the minimum failure weight separating `t` from `s`, or `None` when
/// they are adjacent.
#[must_use]
pub fn min_node_cut_weight(graph: &WeightedGraph, s: u32, t: u32) -> Option<u64> {
    if graph.find_arc(s, t).is_some() {
        return None;
    }
    let n = graph.node_count();
    let candidates: Vec<u32> = (0..n as u32).filter(|&v| v != s && v != t).collect();
    let mut best: Option<u64> = None;
    for mask in 0_u64..(1 << candidates.len()) {
        let removed: BTreeSet<u32> = candidates
            .iter()
            .enumerate()
            .filter(|(bit, _)| mask & (1 << bit) != 0)
            .map(|(_, &v)| v)
            .collect();
        let weight: u64 = removed.iter().map(|&v| graph.node_weight(v)).sum();
        if best.is_some_and(|value| weight >= value) {
            continue;
        }
        if !connected_without(graph, s, t, &removed) {
            best = Some(weight);
        }
    }
    best
}

/// Net flow balance per node of `(tail, head, amount)` flows.
#[must_use]
pub fn balances(flows: &[(String, String, u64)]) -> BTreeMap<String, i128> {
    let mut balance: BTreeMap<String, i128> = BTreeMap::new();
    for (tail, head, amount) in flows {
        *balance.entry(tail.clone()).or_insert(0) -= i128::from(*amount);
        *balance.entry(head.clone()).or_insert(0) += i128::from(*amount);
    }
    balance
}

/// `ALG-MST-001` by enumerating every edge subset: the spanning forest minimizing the
/// perturbed weight `weight * (m + 1) + index` (unique, and a minimum forest of the real
/// weights). Returns `(canonical edge indices, total weight, components)`.
#[must_use]
pub fn minimum_spanning_forest(graph: &WeightedGraph) -> (Vec<u32>, u64, u64) {
    let (n, m) = (graph.node_count(), graph.arc_count());
    let arcs = graph.arcs();
    let mut best: Option<(u128, u64)> = None;
    let mut best_size = 0;
    for mask in 0_u64..(1 << m) {
        let mut parent: Vec<usize> = (0..n).collect();
        fn root(parent: &mut [usize], mut x: usize) -> usize {
            while parent[x] != x {
                x = parent[x];
            }
            x
        }
        let mut acyclic = true;
        let mut size = 0;
        let mut key: u128 = 0;
        for (index, arc) in arcs.iter().enumerate() {
            if mask & (1 << index) == 0 {
                continue;
            }
            let (a, b) = (
                root(&mut parent, arc.tail as usize),
                root(&mut parent, arc.head as usize),
            );
            if a == b {
                acyclic = false;
                break;
            }
            parent[a] = b;
            size += 1;
            key += u128::from(arc.weight) * (m as u128 + 1) + index as u128;
        }
        if !acyclic {
            continue;
        }
        if size > best_size || (size == best_size && best.is_none_or(|(k, _)| key < k)) {
            best_size = size;
            best = Some((key, mask));
        }
    }
    let mask = best.map_or(0, |(_, mask)| mask);
    let edges: Vec<u32> = (0..m as u32).filter(|&e| mask & (1 << e) != 0).collect();
    let total = edges.iter().map(|&e| graph.arc(e).weight).sum();
    (edges.clone(), total, (n - edges.len()) as u64)
}

/// All-pairs minimum cut values of an undirected capacity graph by subset enumeration.
#[must_use]
pub fn all_pairs_min_cut(graph: &WeightedGraph) -> BTreeMap<(u32, u32), u64> {
    let n = graph.node_count() as u32;
    let mut values = BTreeMap::new();
    for a in 0..n {
        for b in a + 1..n {
            values.insert((a, b), min_arc_cut(graph, a, b).value);
        }
    }
    values
}

/// `ALG-MCF-001` by unit augmentations along Bellman–Ford shortest residual paths: returns
/// `(delivered, total cost)`.
#[must_use]
pub fn min_cost_flow(
    costs: &WeightedGraph,
    capacities: &WeightedGraph,
    s: u32,
    t: u32,
    demand: u64,
) -> (u64, u64) {
    let n = costs.node_count();
    let mut residual: Vec<(usize, usize, u64, i128)> = Vec::new();
    for (index, arc) in costs.arcs().iter().enumerate() {
        let cap = capacities.arc(index as u32).weight;
        residual.push((
            arc.tail as usize,
            arc.head as usize,
            cap,
            i128::from(arc.weight),
        ));
        residual.push((
            arc.head as usize,
            arc.tail as usize,
            0,
            -i128::from(arc.weight),
        ));
    }
    let mut delivered = 0;
    let mut total: i128 = 0;
    while delivered < demand {
        let mut distance: Vec<Option<i128>> = vec![None; n];
        let mut via = vec![usize::MAX; n];
        distance[s as usize] = Some(0);
        for _ in 0..n {
            for (edge, &(u, v, cap, cost)) in residual.iter().enumerate() {
                if cap == 0 {
                    continue;
                }
                if let Some(du) = distance[u]
                    && distance[v].is_none_or(|dv| du + cost < dv)
                {
                    distance[v] = Some(du + cost);
                    via[v] = edge;
                }
            }
        }
        let Some(d) = distance[t as usize] else { break };
        let mut node = t as usize;
        while node != s as usize {
            let edge = via[node];
            residual[edge].2 -= 1;
            residual[edge ^ 1].2 += 1;
            node = residual[edge].0;
        }
        total += d;
        delivered += 1;
    }
    (delivered, u64::try_from(total).unwrap_or(u64::MAX))
}

/// Every assignment of `problem`: per left row the chosen right index or `None`.
#[must_use]
pub fn all_assignments(problem: &crate::assignment::AssignmentProblem) -> Vec<Vec<Option<u32>>> {
    let (l, r) = (problem.left().len(), problem.right().len());
    let mut result = Vec::new();
    let mut current: Vec<Option<u32>> = Vec::new();
    let mut used = vec![false; r];
    fn recurse(
        problem: &crate::assignment::AssignmentProblem,
        l: usize,
        current: &mut Vec<Option<u32>>,
        used: &mut Vec<bool>,
        result: &mut Vec<Vec<Option<u32>>>,
    ) {
        let row = current.len();
        if row == l {
            result.push(current.clone());
            return;
        }
        for &(li, ri, _) in problem.pairs() {
            if li as usize == row && !used[ri as usize] {
                used[ri as usize] = true;
                current.push(Some(ri));
                recurse(problem, l, current, used, result);
                current.pop();
                used[ri as usize] = false;
            }
        }
        current.push(None);
        recurse(problem, l, current, used, result);
        current.pop();
    }
    recurse(problem, l, &mut current, &mut used, &mut result);
    result
}

/// `(objective key, tuple)` of one assignment under `policy`, ordering exactly as the certified
/// runs do: maximum cardinality ranks by (fewer unassigned, cost); priced by total objective.
#[must_use]
pub fn assignment_key(
    problem: &crate::assignment::AssignmentProblem,
    policy: crate::assignment::NonAssignment,
    choice: &[Option<u32>],
) -> (i128, Vec<usize>) {
    let r = problem.right().len();
    let matched: u64 = choice
        .iter()
        .enumerate()
        .filter_map(|(row, c)| c.and_then(|c| problem.cost(row as u32, c)))
        .sum();
    let k = choice.iter().filter(|c| c.is_some()).count() as i128;
    let (l, r_count) = (choice.len() as i128, r as i128);
    let key = match policy {
        crate::assignment::NonAssignment::MaximumCardinality => {
            let total: i128 = problem.pairs().iter().map(|&(_, _, c)| i128::from(c)).sum();
            (l + r_count - 2 * k) * (total + 1) + i128::from(matched)
        }
        crate::assignment::NonAssignment::Priced { left, right } => {
            i128::from(matched) + (l - k) * i128::from(left) + (r_count - k) * i128::from(right)
        }
    };
    let tuple = choice
        .iter()
        .enumerate()
        .map(|(row, c)| c.map_or(r + row, |c| c as usize))
        .collect();
    (key, tuple)
}

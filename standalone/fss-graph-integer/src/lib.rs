#![forbid(unsafe_code)]
//! Dependency-free, deterministic graph algorithms for exact integer amounts.
//! This standalone library has no surveillance vocabulary or effect authority.

use std::collections::{BTreeSet, VecDeque};

/// Fail-closed input, resource, arithmetic, and proof errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid or duplicate vertex identity.
    InvalidVertex,
    /// Unknown endpoint, loop, or duplicate arc.
    InvalidArc,
    /// Terminals are missing or equal.
    InvalidTerminals,
    /// Capacity cannot be negative.
    NegativeCapacity,
    /// An exact integer operation overflowed.
    Overflow,
    /// Explicit resource allowance exceeded.
    BudgetExceeded,
    /// The output failed its certificate.
    InvalidCertificate,
}

/// One directed arc; capacity is a nonnegative, exact i128 amount.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapacityArc {
    /// Tail identity.
    pub from: String,
    /// Head identity.
    pub to: String,
    /// Capacity in caller-declared units.
    pub capacity: i128,
}

/// Limits apply to both input size and the complete residual traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowBudget {
    /// Maximum named vertices.
    pub max_vertices: usize,
    /// Maximum arcs.
    pub max_arcs: usize,
    /// Maximum residual edge inspections, including proof reachability.
    pub max_scans: u64,
}

/// Exact max-flow and minimum-cut witness, ordered by stable vertex identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowWitness {
    /// Max flow equals min cut capacity.
    pub value: i128,
    /// Original arcs and their flow, including zero flows.
    pub arc_flows: Vec<(String, String, i128)>,
    /// Vertices reachable from source in the terminal residual graph.
    pub source_side: Vec<String>,
    /// Original arcs crossing that cut.
    pub cut: Vec<CapacityArc>,
    /// Residual edge inspections charged against the budget.
    pub scans: u64,
    /// Successful augmentations.
    pub augmentations: u64,
}

#[derive(Clone)]
struct Edge { to: usize, residual: i128, reverse: usize }

fn charge(scans: &mut u64, maximum: u64) -> Result<(), Error> {
    *scans = scans.checked_add(1).ok_or(Error::Overflow)?;
    if *scans > maximum { Err(Error::BudgetExceeded) } else { Ok(()) }
}

/// Deterministic, bounded Edmonds-Karp flow with a checked min-cut certificate.
///
/// Names and arcs are canonicalized irrespective of input order. This rejects
/// loops, duplicate arcs, negative capacities, invalid terminals and overflow.
/// A result is returned only after independent flow-conservation and cut checks.
/// Complexity is O(V E²); every residual scan is budgeted.
///
/// # Errors
/// Returns `Error` on invalid input, exhausted budget, overflow or a bad proof.
pub fn max_flow_min_cut(
    vertices: &[String], arcs: &[CapacityArc], source: &str, sink: &str,
    budget: FlowBudget,
) -> Result<FlowWitness, Error> {
    if vertices.len() > budget.max_vertices || arcs.len() > budget.max_arcs {
        return Err(Error::BudgetExceeded);
    }
    let mut ids = vertices.to_vec();
    ids.sort();
    if ids.iter().any(|s| s.is_empty() || s.len() > 256 || s.chars().any(char::is_control))
        || ids.windows(2).any(|w| w[0] == w[1]) {
        return Err(Error::InvalidVertex);
    }
    let lookup = |name: &str| ids.binary_search_by(|v| v.as_str().cmp(name)).ok();
    let (Some(s), Some(t)) = (lookup(source), lookup(sink)) else {
        return Err(Error::InvalidTerminals);
    };
    if s == t { return Err(Error::InvalidTerminals); }

    let mut ordered = arcs.to_vec();
    ordered.sort_by(|a, b| (&a.from, &a.to).cmp(&(&b.from, &b.to)));
    let mut seen = BTreeSet::new();
    let mut adjacency = vec![Vec::<usize>::new(); ids.len()];
    let mut edges = Vec::<Edge>::new();
    let mut originals = Vec::new();
    for arc in &ordered {
        let (Some(a), Some(b)) = (lookup(&arc.from), lookup(&arc.to)) else {
            return Err(Error::InvalidArc);
        };
        if a == b || !seen.insert((a,b)) { return Err(Error::InvalidArc); }
        if arc.capacity < 0 { return Err(Error::NegativeCapacity); }
        let e = edges.len();
        edges.push(Edge { to: b, residual: arc.capacity, reverse: e+1 });
        edges.push(Edge { to: a, residual: 0, reverse: e });
        adjacency[a].push(e);
        adjacency[b].push(e+1);
        originals.push(e);
    }
    let mut scans = 0;
    let mut augmentations = 0_u64;
    let mut value = 0_i128;
    loop {
        let mut parent = vec![None::<usize>; ids.len()];
        let mut visited = vec![false; ids.len()];
        let mut queue = VecDeque::from([s]);
        visited[s] = true;
        'search: while let Some(node) = queue.pop_front() {
            for &e in &adjacency[node] {
                charge(&mut scans, budget.max_scans)?;
                let next = edges[e].to;
                if edges[e].residual > 0 && !visited[next] {
                    visited[next] = true;
                    parent[next] = Some(e);
                    if next == t { break 'search; }
                    queue.push_back(next);
                }
            }
        }
        if !visited[t] { break; }
        let mut delta = i128::MAX;
        let mut cur = t;
        while cur != s {
            let e = parent[cur].ok_or(Error::InvalidCertificate)?;
            delta = delta.min(edges[e].residual);
            cur = edges[edges[e].reverse].to;
        }
        let new_value = value.checked_add(delta).ok_or(Error::Overflow)?;
        cur = t;
        while cur != s {
            let e = parent[cur].ok_or(Error::InvalidCertificate)?;
            edges[edges[e].reverse].residual.checked_add(delta).ok_or(Error::Overflow)?;
            cur = edges[edges[e].reverse].to;
        }
        cur = t;
        while cur != s {
            let e = parent[cur].ok_or(Error::InvalidCertificate)?;
            edges[e].residual -= delta;
            let reverse = edges[e].reverse;
            edges[reverse].residual += delta;
            cur = edges[reverse].to;
        }
        value = new_value;
        augmentations = augmentations.checked_add(1).ok_or(Error::Overflow)?;
    }
    // Recompute terminal reachability and bill this certification pass.
    let mut reachable = vec![false; ids.len()];
    reachable[s] = true;
    let mut queue = VecDeque::from([s]);
    while let Some(node) = queue.pop_front() {
        for &e in &adjacency[node] {
            charge(&mut scans, budget.max_scans)?;
            let next = edges[e].to;
            if edges[e].residual > 0 && !reachable[next] {
                reachable[next] = true;
                queue.push_back(next);
            }
        }
    }
    if reachable[t] { return Err(Error::InvalidCertificate); }
    let mut balances = vec![0_i128; ids.len()];
    let mut cut_value = 0_i128;
    let mut cut = Vec::new();
    let mut arc_flows = Vec::new();
    for (arc, &e) in ordered.iter().zip(originals.iter()) {
        let flow = arc.capacity.checked_sub(edges[e].residual).ok_or(Error::Overflow)?;
        if flow < 0 || flow > arc.capacity { return Err(Error::InvalidCertificate); }
        let a = lookup(&arc.from).ok_or(Error::InvalidCertificate)?;
        let b = lookup(&arc.to).ok_or(Error::InvalidCertificate)?;
        balances[a] = balances[a].checked_sub(flow).ok_or(Error::Overflow)?;
        balances[b] = balances[b].checked_add(flow).ok_or(Error::Overflow)?;
        if reachable[a] && !reachable[b] {
            cut_value = cut_value.checked_add(arc.capacity).ok_or(Error::Overflow)?;
            cut.push(arc.clone());
        }
        arc_flows.push((arc.from.clone(), arc.to.clone(), flow));
    }
    if cut_value != value || balances[s] != -value || balances[t] != value
        || balances.iter().enumerate().any(|(v, &b)| v != s && v != t && b != 0) {
        return Err(Error::InvalidCertificate);
    }
    let source_side = ids.into_iter().enumerate()
        .filter_map(|(v, name)| reachable[v].then_some(name)).collect();
    Ok(FlowWitness { value, arc_flows, source_side, cut, scans, augmentations })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn budget() -> FlowBudget {
        FlowBudget { max_vertices: 64, max_arcs: 256, max_scans: 100_000 }
    }
    fn arc(from: &str, to: &str, capacity: i128) -> CapacityArc {
        CapacityArc { from: from.into(), to: to.into(), capacity }
    }
    #[test]
    fn larger_than_u64_and_order_independent() {
        let vertices = vec!["t".into(), "s".into(), "a".into(), "b".into()];
        let big = i128::from(u64::MAX) + 10;
        let arcs = vec![arc("s","b",big), arc("b","t",big),
                        arc("s","a",big), arc("a","t",big)];
        let out = max_flow_min_cut(&vertices, &arcs, "s", "t", budget()).unwrap();
        assert_eq!(out.value, 2 * big);
        assert_eq!(out.cut.len(), 2);
        let mut reversed = arcs.clone(); reversed.reverse();
        assert_eq!(out, max_flow_min_cut(&vertices, &reversed, "s", "t", budget()).unwrap());
    }
    #[test]
    fn missing_path_and_isolated_vertex() {
        let v = vec!["a".into(), "b".into(), "c".into()];
        let out = max_flow_min_cut(&v, &[], "a", "c", budget()).unwrap();
        assert_eq!(out.value, 0);
        assert_eq!(out.source_side, vec!["a".to_string()]);
    }
    #[test]
    fn invalid_input_and_budget_refused() {
        let v = vec!["a".into(), "b".into()];
        assert_eq!(max_flow_min_cut(&v, &[arc("a","b",-1)], "a", "b", budget()), Err(Error::NegativeCapacity));
        assert_eq!(max_flow_min_cut(&v, &[arc("a","b",1),arc("a","b",2)], "a", "b", budget()), Err(Error::InvalidArc));
        assert_eq!(max_flow_min_cut(&v, &[arc("a","b",1)], "a", "b",
            FlowBudget { max_scans: 0, ..budget() }), Err(Error::BudgetExceeded));
    }
    #[test]
    fn overflow_refused() {
        let v = vec!["s".into(), "t".into(), "a".into(), "b".into()];
        let e = vec![arc("s","a",i128::MAX), arc("a","t",i128::MAX),
                     arc("s","b",1), arc("b","t",1)];
        assert_eq!(max_flow_min_cut(&v, &e, "s", "t", budget()), Err(Error::Overflow));
    }
}

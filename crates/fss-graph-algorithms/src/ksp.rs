//! `ALG-KSP-001` — k shortest loopless paths with an explicit diversity constraint.
//!
//! Yen's algorithm over exact `u64` lengths, directed or undirected, under the strict total path
//! order `(cost, hops, node identity sequence)`. Every spur search returns the minimum spur under
//! that same order (reverse lexicographic Dijkstra to the target, then a greedy forward walk
//! taking the smallest-identity tight successor), so the enumeration is exactly the ascending
//! sequence of loopless paths in that order — ties never depend on heap or insertion order.
//!
//! Diversity: with `min_distinct_arcs = d > 0`, an enumerated path is *admitted* only when, for
//! every already admitted path, at least `d` of its arcs are not arcs of that path; rejected
//! paths still seed later spurs (they are real alternatives, just too similar to report). The
//! answer reports how many paths were enumerated and rejected, and whether the enumeration was
//! exhausted (no further loopless path exists) or stopped at the declared `max_enumerated` cap —
//! a capped search never claims there are no more alternatives.

use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap};

use fss_core::CanonicalEncoder;

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, checked_add, encode_ids, mul, query_digest, query_encoder,
};
use crate::graph::GraphError;
use crate::paths::scan_entries;
use crate::weighted::{Orientation, WeightedGraph};

/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-KSP-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.ksp_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-KSP-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.ksp_decision_path.v1";
/// Maximum `k` and maximum enumeration cap of one query.
pub const MAX_PATHS: u32 = 1024;

/// Registered identity (`ALG-KSP-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-KSP-001",
    algorithm_name: "k_shortest_diverse_paths",
    tie_break_rule: "cost, diversity penalty, then stable path identity",
    complexity_witness: "candidate expansions and heap operations",
    output_size_witness: "<= k * |V| path nodes and <= k * |E| edges",
    exactness: "exact_or_bounded",
    implementation_id: "fss-graph-algorithms:alg-ksp-001:yen-lexicographic-spur-diversity-filter:v1",
    tie_break_policy_id: "tie:cost-then-hops-then-lexicographic-node-identity-sequence:v1",
    policy_id: "graph-policy:directed-or-undirected:simple-strict:loopless:nonnegative-arc-length:min-distinct-arcs-diversity:numeric:u64-exact:checked:unit-bound:v1:tie:cost-then-hops-then-lexicographic-node-identity-sequence:v1",
    complexity_bound_id: "bound:alg-ksp-001:yen-cap-times-n-spur-searches:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// The registered bound for `n` nodes, `m` arcs, and the enumeration cap `cap`.
#[must_use]
pub fn bound(orientation: Orientation, n: u64, m: u64, k: u64, cap: u64) -> Vec<BoundRow> {
    let r = scan_entries(orientation, m);
    let searches = add(mul(cap, n), 1);
    vec![
        ("spur_searches", searches),
        ("relaxations", mul(searches, r)),
        ("heap_operations", mul(searches, mul(2, add(r, 1)))),
        ("walk_scans", mul(searches, r)),
        ("candidate_expansions", mul(searches, add(n, 1))),
        ("diversity_checks", mul(cap, mul(k, add(n, 1)))),
        (OUTPUT_ENTRIES, mul(k, n)),
    ]
}

/// One reported path.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RankedPath {
    /// Exact total length.
    pub cost: u64,
    /// Arcs.
    pub hops: u64,
    /// Node identities from source to target.
    pub nodes: Vec<String>,
}

/// Why enumeration stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KspStop {
    /// `k` diverse paths were admitted.
    Satisfied,
    /// Every loopless path was enumerated.
    Exhausted,
    /// The declared enumeration cap was reached first; more paths may exist.
    EnumerationCap,
}

impl KspStop {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Satisfied => "satisfied",
            Self::Exhausted => "exhausted",
            Self::EnumerationCap => "enumeration_cap",
        }
    }
}

/// The canonical answer of `ALG-KSP-001`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KspOutput {
    /// Source.
    pub source: String,
    /// Target.
    pub target: String,
    /// Requested `k`.
    pub requested: u32,
    /// Diversity threshold.
    pub min_distinct_arcs: u32,
    /// Admitted paths in ascending `(cost, hops, sequence)` order.
    pub paths: Vec<RankedPath>,
    /// Loopless paths enumerated (admitted or rejected).
    pub enumerated: u32,
    /// Enumerated paths rejected as too similar.
    pub rejected_for_diversity: u32,
    /// Why enumeration stopped.
    pub stop: KspStop,
}

impl CertifiedOutput for KspOutput {
    fn entries(&self) -> u64 {
        self.paths.iter().map(|path| path.nodes.len() as u64).sum()
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.source);
        encoder.text(&self.target);
        encoder.u32(self.requested);
        encoder.u32(self.min_distinct_arcs);
        encoder.u64(self.paths.len() as u64);
        for path in &self.paths {
            encoder.u64(path.cost);
            encoder.u64(path.hops);
            encode_ids(encoder, &path.nodes);
        }
        encoder.u32(self.enumerated);
        encoder.u32(self.rejected_for_diversity);
        encoder.text(self.stop.as_str());
    }
}

/// `(cost, hops, node sequence)` of one candidate.
type Candidate = (u64, u64, Vec<u32>);

/// The minimum path from `from` to `to` under `(cost, hops, sequence)` avoiding `banned_nodes`
/// and `banned_arcs`, as `(cost, hops, nodes)`.
fn spur_path(
    graph: &WeightedGraph,
    from: u32,
    to: u32,
    banned_nodes: &[bool],
    banned_arcs: &BTreeSet<u32>,
    meter: &mut Meter,
) -> Result<Option<Candidate>, GraphError> {
    meter.tick("spur_searches")?;
    let n = graph.node_count();
    let directed = graph.orientation() == Orientation::Directed;
    // Reverse Dijkstra: key[v] = (distance, hops) from v to `to`.
    let mut key: Vec<Option<(u64, u64)>> = vec![None; n];
    let mut done = vec![false; n];
    let mut heap: BinaryHeap<Reverse<((u64, u64), u32)>> = BinaryHeap::new();
    if banned_nodes[to as usize] {
        return Ok(None);
    }
    key[to as usize] = Some((0, 0));
    meter.tick("heap_operations")?;
    heap.push(Reverse(((0, 0), to)));
    while let Some(Reverse((current, v))) = heap.pop() {
        meter.tick("heap_operations")?;
        if done[v as usize] || key[v as usize] != Some(current) {
            continue;
        }
        done[v as usize] = true;
        let incoming = if directed {
            graph.in_arcs(v)
        } else {
            graph.out_arcs(v)
        };
        for &arc_index in incoming {
            meter.tick("relaxations")?;
            if banned_arcs.contains(&arc_index) {
                continue;
            }
            let arc = graph.arc(arc_index);
            let u = if directed { arc.tail } else { arc.other(v) };
            if banned_nodes[u as usize] || done[u as usize] {
                continue;
            }
            let candidate = (
                checked_add(current.0, arc.weight, "path cost")?,
                current.1 + 1,
            );
            if key[u as usize].is_none_or(|existing| candidate < existing) {
                key[u as usize] = Some(candidate);
                meter.tick("heap_operations")?;
                heap.push(Reverse((candidate, u)));
            }
        }
    }
    let Some(total) = key[from as usize] else {
        return Ok(None);
    };
    let mut nodes = vec![from];
    let mut current = from;
    while current != to {
        let mut next = None;
        let (distance, hops) = key[current as usize].unwrap_or((0, 0));
        for &arc_index in graph.out_arcs(current) {
            meter.tick("walk_scans")?;
            if banned_arcs.contains(&arc_index) {
                continue;
            }
            let arc = graph.arc(arc_index);
            let v = if directed {
                arc.head
            } else {
                arc.other(current)
            };
            if let Some((dv, hv)) = key[v as usize]
                && !banned_nodes[v as usize]
                && dv.checked_add(arc.weight) == Some(distance)
                && hv + 1 == hops
                && next.is_none_or(|best| v < best)
            {
                next = Some(v);
            }
        }
        let Some(v) = next else {
            return Err(GraphError::Inconsistent(
                "a spur walk lost its tight successor".to_owned(),
            ));
        };
        nodes.push(v);
        current = v;
    }
    Ok(Some((total.0, total.1, nodes)))
}

/// The arc index joining consecutive path nodes.
fn arc_between(graph: &WeightedGraph, a: u32, b: u32) -> Result<u32, GraphError> {
    graph
        .find_arc(a, b)
        .ok_or_else(|| GraphError::Inconsistent("a path step has no arc".to_owned()))
}

/// Runs `ALG-KSP-001`: up to `k` admitted loopless paths from `source` to `target`, enumerating
/// at most `max_enumerated` paths in total.
///
/// # Errors
///
/// [`GraphError::PreconditionFailed`] for equal terminals, `k = 0`, or `k`/cap outside
/// `1..=MAX_PATHS` or `cap < k`; [`GraphError::UnknownNode`]; [`GraphError::ArithmeticOverflow`];
/// and the fail-closed budget and bound errors.
pub fn k_shortest_paths(
    graph: &WeightedGraph,
    source: &str,
    target: &str,
    k: u32,
    min_distinct_arcs: u32,
    max_enumerated: u32,
    budget: Budget,
) -> Result<CertifiedRun<KspOutput>, GraphError> {
    let s = graph.require(source)?;
    let t = graph.require(target)?;
    if s == t {
        return Err(GraphError::PreconditionFailed(
            "paths need distinct terminals".to_owned(),
        ));
    }
    if k == 0 || k > MAX_PATHS || max_enumerated < k || max_enumerated > MAX_PATHS {
        return Err(GraphError::PreconditionFailed(format!(
            "need 1 <= k <= max_enumerated <= {MAX_PATHS}"
        )));
    }
    let n = graph.node_count();
    let mut meter = Meter::new(&IDENTITY, budget);
    let no_nodes = vec![false; n];
    let mut enumerated: Vec<Candidate> = Vec::new();
    let mut candidates: BTreeSet<Candidate> = BTreeSet::new();
    let mut admitted: Vec<(Candidate, BTreeSet<u32>)> = Vec::new();
    let mut rejected = 0_u32;
    let mut stop = KspStop::Exhausted;
    if let Some(first) = spur_path(graph, s, t, &no_nodes, &BTreeSet::new(), &mut meter)? {
        candidates.insert(first);
    }
    while let Some(best) = candidates.pop_first() {
        if enumerated.len() as u32 >= max_enumerated {
            stop = KspStop::EnumerationCap;
            break;
        }
        let arcs: BTreeSet<u32> = best
            .2
            .windows(2)
            .map(|pair| arc_between(graph, pair[0], pair[1]))
            .collect::<Result<_, _>>()?;
        let mut diverse = true;
        for (_, other) in &admitted {
            meter.tick("diversity_checks")?;
            if (arcs.difference(other).count() as u32) < min_distinct_arcs {
                diverse = false;
                break;
            }
        }
        meter.decide(u8::from(diverse), enumerated.len() as u64, best.0);
        enumerated.push(best.clone());
        if diverse {
            admitted.push((best.clone(), arcs));
            if admitted.len() as u32 == k {
                stop = KspStop::Satisfied;
                break;
            }
        } else {
            rejected += 1;
        }
        // Spur candidates from the newest enumerated path.
        let path = &best.2;
        let mut root_cost = 0_u64;
        for i in 0..path.len() - 1 {
            meter.tick("candidate_expansions")?;
            let spur = path[i];
            let root = &path[..=i];
            let mut banned_arcs = BTreeSet::new();
            for (_, _, other) in &enumerated {
                if other.len() > i + 1 && &other[..=i] == root {
                    banned_arcs.insert(arc_between(graph, other[i], other[i + 1])?);
                }
            }
            let mut banned_nodes = vec![false; n];
            for &node in &root[..i] {
                banned_nodes[node as usize] = true;
            }
            if let Some((cost, hops, tail)) =
                spur_path(graph, spur, t, &banned_nodes, &banned_arcs, &mut meter)?
            {
                let mut nodes = root[..i].to_vec();
                nodes.extend(tail);
                let total = (
                    checked_add(root_cost, cost, "path cost")?,
                    i as u64 + hops,
                    nodes,
                );
                if !enumerated.contains(&total) {
                    candidates.insert(total);
                }
            }
            let step = graph.arc(arc_between(graph, path[i], path[i + 1])?).weight;
            root_cost = checked_add(root_cost, step, "path cost")?;
        }
    }
    let ids = |nodes: &[u32]| {
        nodes
            .iter()
            .map(|&node| graph.id(node).to_owned())
            .collect()
    };
    let output = KspOutput {
        source: source.to_owned(),
        target: target.to_owned(),
        requested: k,
        min_distinct_arcs,
        paths: admitted
            .iter()
            .map(|((cost, hops, nodes), _)| RankedPath {
                cost: *cost,
                hops: *hops,
                nodes: ids(nodes),
            })
            .collect(),
        enumerated: enumerated.len() as u32,
        rejected_for_diversity: rejected,
        stop,
    };
    let (n64, m64) = (n as u64, graph.arc_count() as u64);
    let mut input = query_encoder(&IDENTITY, graph.digest());
    input.text(source);
    input.text(target);
    input.u32(k);
    input.u32(min_distinct_arcs);
    input.u32(max_enumerated);
    let peak = n64 * 26 + (enumerated.len() + candidates.len()) as u64 * (16 + 4 * n64);
    meter.finish(
        &IDENTITY,
        InputShape {
            node_count: n64,
            edge_count: m64,
            input_digest: query_digest(input),
        },
        output,
        &bound(
            graph.orientation(),
            n64,
            m64,
            u64::from(k),
            u64::from(max_enumerated),
        ),
        peak,
    )
}

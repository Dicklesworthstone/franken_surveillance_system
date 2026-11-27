#![forbid(unsafe_code)]
//! `ALG-PLANAR-001` — Exact planarity and declared-layer geometric consistency checks
//! (`fss-x4a.23.70.6`).
//!
//! Validates a single explicitly declared 2D property layer (floor, walkway map, or fence graph)
//! using exact biconnected-component decomposition + Demoucron–Malgrange–Pertuiset (DMP) planar
//! face embedding with Euler self-certification (`V - E + F = 2`).
//!
//! Explicitly names the `declared_layer_id`, `geometry_generation`, and
//! `ignored_crossings_overpasses`, and enforces `replaces_metric_calibration == false` and
//! `implies_global_3d_planarity == false` (a real 3D property is not globally planar!).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fss_core::{CanonicalEncoder, Generation};

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, mul, query_digest, query_encoder,
};
use crate::graph::{GraphError, UndirectedGraph};

/// Projection digest domain (`SCHEMA-DOMAIN-GRAPH-PLANAR-PROJECTION-001`).
pub const PROJECTION_DOMAIN: &str = "fss.graph.planar_projection.v1";
/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-PLANAR-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.planar_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-PLANAR-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.planar_decision_path.v1";

/// Registered identity (`architecture/graph_algorithms.json`, `ALG-PLANAR-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-PLANAR-001",
    algorithm_name: "planarity_and_layer_consistency",
    tie_break_rule: "declared layer then stable node and edge identity",
    complexity_witness: "biconnected DFS visits, DMP fragment scans, and face splits",
    output_size_witness: "<= |F| <= 2|V| face cycles or nonplanarity obstruction witness",
    exactness: "exact",
    implementation_id: "fss-graph-algorithms:alg-planar-001:exact-dmp-planar-embedding:v1",
    tie_break_policy_id: "tie:declared-layer-then-ascending-node-and-face-order:v1",
    policy_id: "graph-policy:undirected:declared-2d-layer:exact-dmp-planarity:no-metric-replacement:tie:declared-layer-then-ascending-node-and-face-order:v1",
    complexity_bound_id: "bound:alg-planar-001:biconnected-plus-dmp-quadratic:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// Declared 2D layer context bound into the planarity query & output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclaredLayerSpec {
    /// Named 2D property layer (e.g. `"ground_walkways_2d"`, `"fence_perimeter_2d"`).
    pub declared_layer_id: String,
    /// Pinned geometry generation (`>= 1`).
    pub geometry_generation: Generation,
    /// Explicitly declared 3D crossings/overpasses excluded from this 2D layer check.
    pub ignored_crossings_overpasses: Vec<String>,
}

/// Exact planarity verdict for one declared 2D layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanarityVerdict {
    /// Declared 2D layer is planar, witnessed by Euler-verified combinatorial face cycles per block!
    Planar {
        /// Combinatorial face boundary cycles (ordered node IDs) across all biconnected blocks.
        face_cycles: Vec<Vec<String>>,
    },
    /// Declared 2D layer is nonplanar, witnessed by an exact obstruction reason and conflict nodes!
    NonPlanar {
        /// Exact obstruction reason (`euler_edge_bound_exceeded`, `triangle_free_euler_bound_exceeded`, `dmp_conflicting_fragment_k5_or_k33_obstruction`).
        obstruction_kind: String,
        /// Sorted witness node IDs participating in the nonplanar block/fragment.
        witness_nodes: Vec<String>,
    },
}

/// Canonical answer of `ALG-PLANAR-001`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LayerPlanarityResult {
    /// Declared 2D layer audited.
    pub declared_layer_id: String,
    /// Pinned geometry generation.
    pub geometry_generation: Generation,
    /// Explicitly ignored 3D crossings/overpasses (sorted).
    pub ignored_crossings_overpasses: Vec<String>,
    /// Exact planarity verdict.
    pub verdict: PlanarityVerdict,
    /// Always `false`: 2D layer planarity NEVER replaces metric camera calibration!
    pub replaces_metric_calibration: bool,
    /// Always `false`: 2D layer planarity NEVER implies global 3D site planarity!
    pub implies_global_3d_planarity: bool,
    /// Always `false`: derived geometry audit NEVER grants effect authority.
    pub grants_effect_authority: bool,
}

impl CertifiedOutput for LayerPlanarityResult {
    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(&self.declared_layer_id);
        encoder.u64(self.geometry_generation.0);
        encoder.u64(self.ignored_crossings_overpasses.len() as u64);
        for ig in &self.ignored_crossings_overpasses {
            encoder.text(ig);
        }
        match &self.verdict {
            PlanarityVerdict::Planar { face_cycles } => {
                encoder.u8(1);
                encoder.u64(face_cycles.len() as u64);
                for f in face_cycles {
                    encoder.u64(f.len() as u64);
                    for id in f {
                        encoder.text(id);
                    }
                }
            }
            PlanarityVerdict::NonPlanar {
                obstruction_kind,
                witness_nodes,
            } => {
                encoder.u8(2);
                encoder.text(obstruction_kind);
                encoder.u64(witness_nodes.len() as u64);
                for id in witness_nodes {
                    encoder.text(id);
                }
            }
        }
    }

    fn entries(&self) -> u64 {
        match &self.verdict {
            PlanarityVerdict::Planar { face_cycles } => face_cycles.len() as u64,
            PlanarityVerdict::NonPlanar { witness_nodes, .. } => witness_nodes.len() as u64,
        }
    }
}

/// Registered complexity bound for `n` nodes and `m` edges.
#[must_use]
pub fn bound(n: u64, m: u64) -> Vec<BoundRow> {
    let per_iter = add(mul(2, mul(n, m)), mul(2, mul(n, n)));
    let dmp_work = add(mul(m, per_iter), mul(8, add(n, m)));
    vec![
        ("dmp_steps", add(dmp_work, 16)),
        (OUTPUT_ENTRIES, add(mul(2, n), 4)),
    ]
}

/// Runs `ALG-PLANAR-001` exact planarity check on `graph` for `layer`.
pub fn check_declared_layer_planarity(
    graph: &UndirectedGraph,
    layer: &DeclaredLayerSpec,
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<CertifiedRun<LayerPlanarityResult>, GraphError> {
    if layer.declared_layer_id.is_empty() || layer.geometry_generation.0 == 0 {
        return Err(GraphError::PreconditionFailed(
            "declared_layer_id must be non-empty and geometry_generation >= 1".to_owned(),
        ));
    }
    let n = graph.node_count();
    let m = graph.edge_count();
    let bound_rows = bound(n as u64, m as u64);
    let mut meter = Meter::new_cancellable(&IDENTITY, budget, is_cancelled);

    let mut ignored = layer.ignored_crossings_overpasses.clone();
    ignored.sort();
    ignored.dedup();

    let mut q = query_encoder(&IDENTITY, graph.digest());
    q.text(&layer.declared_layer_id);
    q.u64(layer.geometry_generation.0);
    q.u64(ignored.len() as u64);
    for ig in &ignored {
        q.text(ig);
    }
    let input_digest = query_digest(q);

    let blocks = biconnected_edge_blocks(graph, &mut meter)?;
    let mut all_faces: Vec<Vec<String>> = Vec::new();
    let mut nonplanar_witness: Option<(String, Vec<String>)> = None;

    for block_edges in blocks {
        let mut verts_set = BTreeSet::new();
        for &(u, v) in &block_edges {
            verts_set.insert(u);
            verts_set.insert(v);
        }
        let verts: Vec<usize> = verts_set.into_iter().collect();
        if verts.len() < 3 || block_edges.len() < 3 {
            continue;
        }
        match test_biconnected_block_dmp(&verts, &block_edges, &mut meter)? {
            BlockPlanarity::Planar(block_faces) => {
                for face in block_faces {
                    let names: Vec<String> = face
                        .into_iter()
                        .map(|u| graph.id(u as u32).to_owned())
                        .collect();
                    all_faces.push(names);
                }
            }
            BlockPlanarity::NonPlanar { kind, nodes } => {
                let mut witness_nodes: Vec<String> = nodes
                    .into_iter()
                    .map(|u| graph.id(u as u32).to_owned())
                    .collect();
                witness_nodes.sort();
                witness_nodes.dedup();
                nonplanar_witness = Some((kind, witness_nodes));
                break;
            }
        }
    }

    let verdict = match nonplanar_witness {
        Some((obstruction_kind, witness_nodes)) => {
            meter.path().text(&obstruction_kind);
            for w in &witness_nodes {
                meter.path().text(w);
            }
            PlanarityVerdict::NonPlanar {
                obstruction_kind,
                witness_nodes,
            }
        }
        None => {
            all_faces.sort();
            meter.path().text("planar");
            meter.path().u64(all_faces.len() as u64);
            PlanarityVerdict::Planar {
                face_cycles: all_faces,
            }
        }
    };

    let output = LayerPlanarityResult {
        declared_layer_id: layer.declared_layer_id.clone(),
        geometry_generation: layer.geometry_generation,
        ignored_crossings_overpasses: ignored,
        verdict,
        replaces_metric_calibration: false,
        implies_global_3d_planarity: false,
        grants_effect_authority: false,
    };
    let shape = InputShape {
        node_count: n as u64,
        edge_count: m as u64,
        input_digest,
    };
    let peak_bytes = ((n + m + 1) * 192) as u64;
    meter.finish(&IDENTITY, shape, output, &bound_rows, peak_bytes)
}

enum BlockPlanarity {
    Planar(Vec<Vec<usize>>),
    NonPlanar { kind: String, nodes: Vec<usize> },
}

/// Iterative Tarjan biconnected edge-block decomposition.
fn biconnected_edge_blocks(
    graph: &UndirectedGraph,
    meter: &mut Meter<'_>,
) -> Result<Vec<Vec<(usize, usize)>>, GraphError> {
    let n = graph.node_count();
    let mut disc = vec![0_u32; n];
    let mut low = vec![0_u32; n];
    let mut parent = vec![usize::MAX; n];
    let mut timer = 0_u32;
    let mut edge_stack: Vec<(usize, usize)> = Vec::new();
    let mut blocks: Vec<Vec<(usize, usize)>> = Vec::new();

    for root in 0..n {
        if disc[root] != 0 {
            continue;
        }
        timer += 1;
        disc[root] = timer;
        low[root] = timer;
        let mut dfs: Vec<(usize, usize)> = vec![(root, 0)];
        while let Some((u, idx)) = dfs.pop() {
            meter.tick("dmp_steps")?;
            let nbrs = graph.neighbours(u as u32);
            if idx < nbrs.len() {
                dfs.push((u, idx + 1));
                let v = nbrs[idx].0 as usize;
                if disc[v] == 0 {
                    parent[v] = u;
                    edge_stack.push((u.min(v), u.max(v)));
                    timer += 1;
                    disc[v] = timer;
                    low[v] = timer;
                    dfs.push((v, 0));
                } else if v != parent[u] && disc[v] < disc[u] {
                    edge_stack.push((u.min(v), u.max(v)));
                    low[u] = low[u].min(disc[v]);
                }
            } else if parent[u] != usize::MAX {
                let p = parent[u];
                low[p] = low[p].min(low[u]);
                if low[u] >= disc[p] {
                    let target = (p.min(u), p.max(u));
                    let mut block = Vec::new();
                    while let Some(e) = edge_stack.pop() {
                        block.push(e);
                        if e == target {
                            break;
                        }
                    }
                    block.sort_unstable();
                    blocks.push(block);
                }
            }
        }
    }
    Ok(blocks)
}

/// Exact Demoucron–Malgrange–Pertuiset (DMP) planarity test & face embedding on a biconnected block.
fn test_biconnected_block_dmp(
    verts: &[usize],
    block_edges: &[(usize, usize)],
    meter: &mut Meter<'_>,
) -> Result<BlockPlanarity, GraphError> {
    let nb = verts.len();
    let mb = block_edges.len();

    // Necessary Euler bound for simple planar graphs (`n >= 3`).
    if mb > 3 * nb - 6 {
        return Ok(BlockPlanarity::NonPlanar {
            kind: "euler_edge_bound_exceeded".to_owned(),
            nodes: verts.to_vec(),
        });
    }

    let mut local_idx: BTreeMap<usize, usize> = BTreeMap::new();
    for (i, &v) in verts.iter().enumerate() {
        local_idx.insert(v, i);
    }
    let mut adj: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); nb];
    let mut local_edges: BTreeSet<(usize, usize)> = BTreeSet::new();
    for &(u, v) in block_edges {
        let lu = local_idx[&u];
        let lv = local_idx[&v];
        adj[lu].insert(lv);
        adj[lv].insert(lu);
        local_edges.insert((lu.min(lv), lu.max(lv)));
    }

    // Check triangle-free Euler bound (`m <= 2n - 4`).
    let mut has_triangle = false;
    'tri: for &(u, v) in &local_edges {
        for &w in &adj[u] {
            meter.tick("dmp_steps")?;
            if adj[v].contains(&w) {
                has_triangle = true;
                break 'tri;
            }
        }
    }
    if !has_triangle && mb > 2 * nb - 4 {
        return Ok(BlockPlanarity::NonPlanar {
            kind: "triangle_free_euler_bound_exceeded".to_owned(),
            nodes: verts.to_vec(),
        });
    }

    // Find an initial simple cycle in the biconnected block via BFS shortest path after removing one edge.
    let &(e0_u, e0_v) = local_edges
        .first()
        .ok_or_else(|| GraphError::PreconditionFailed("empty biconnected block".to_owned()))?;
    let cycle_path = shortest_path_avoiding_edge(e0_u, e0_v, &adj, (e0_u, e0_v), meter)?;
    let Some(cycle) = cycle_path else {
        return Ok(BlockPlanarity::Planar(Vec::new()));
    };

    let mut in_h = vec![false; nb];
    let mut edge_in_h: BTreeSet<(usize, usize)> = BTreeSet::new();
    for &v in &cycle {
        in_h[v] = true;
    }
    for i in 0..cycle.len() {
        let a = cycle[i];
        let b = cycle[(i + 1) % cycle.len()];
        edge_in_h.insert((a.min(b), a.max(b)));
    }
    let mut rev_cycle = cycle.clone();
    rev_cycle.reverse();
    let mut faces: Vec<Vec<usize>> = vec![cycle, rev_cycle];

    while edge_in_h.len() < local_edges.len() {
        meter.tick("dmp_steps")?;
        // 1. Enumerate all fragments (chords + components of B - V(H)).
        let mut fragments: Vec<(BTreeSet<usize>, Vec<usize>)> = Vec::new();
        for &(u, v) in &local_edges {
            if !edge_in_h.contains(&(u, v)) && in_h[u] && in_h[v] {
                let mut att = BTreeSet::new();
                att.insert(u);
                att.insert(v);
                fragments.push((att, vec![u, v]));
            }
        }
        let mut comp_seen = vec![false; nb];
        for start in 0..nb {
            if in_h[start] || comp_seen[start] {
                continue;
            }
            let mut comp_nodes = BTreeSet::new();
            let mut att = BTreeSet::new();
            let mut q = VecDeque::new();
            comp_seen[start] = true;
            comp_nodes.insert(start);
            q.push_back(start);
            while let Some(u) = q.pop_front() {
                meter.tick("dmp_steps")?;
                for &w in &adj[u] {
                    if in_h[w] {
                        att.insert(w);
                    } else if !comp_seen[w] {
                        comp_seen[w] = true;
                        comp_nodes.insert(w);
                        q.push_back(w);
                    }
                }
            }
            // Extract a canonical path between the first two attachments strictly through `comp_nodes`.
            let att_vec: Vec<usize> = att.iter().copied().collect();
            if att_vec.len() >= 2 {
                let path =
                    path_through_component(att_vec[0], att_vec[1], &comp_nodes, &adj, meter)?;
                if let Some(p) = path {
                    fragments.push((att, p));
                }
            }
        }

        // 2. For every fragment find admissible faces containing ALL its attachment vertices.
        let mut chosen: Option<(usize, usize, Vec<usize>, BTreeSet<usize>)> = None;
        for (att, path) in fragments {
            let mut admissible = Vec::new();
            for (fi, face) in faces.iter().enumerate() {
                meter.tick("dmp_steps")?;
                if att.iter().all(|a| face.contains(a)) {
                    admissible.push(fi);
                }
            }
            if admissible.is_empty() {
                let mut witness: Vec<usize> = att.into_iter().map(|i| verts[i]).collect();
                for &p in &path {
                    witness.push(verts[p]);
                }
                return Ok(BlockPlanarity::NonPlanar {
                    kind: "dmp_conflicting_fragment_k5_or_k33_obstruction".to_owned(),
                    nodes: witness,
                });
            }
            let count = admissible.len();
            let fi = admissible[0];
            let replace = match &chosen {
                None => true,
                Some((best_cnt, _, best_path, _)) => {
                    (count, path.as_slice()) < (*best_cnt, best_path.as_slice())
                }
            };
            if replace {
                chosen = Some((count, fi, path, att));
            }
        }

        let Some((_, face_idx, path, _)) = chosen else {
            break;
        };
        // 3. Embed `path` inside `faces[face_idx]`, splitting it into two valid faces!
        let a = path[0];
        let b = path[path.len() - 1];
        let old_face = faces.remove(face_idx);
        let pos_a = old_face
            .iter()
            .position(|&x| x == a)
            .ok_or_else(|| GraphError::Inconsistent("attachment missing from face".to_owned()))?;
        let pos_b = old_face
            .iter()
            .position(|&x| x == b)
            .ok_or_else(|| GraphError::Inconsistent("attachment missing from face".to_owned()))?;

        let flen = old_face.len();
        let mut arc_ab = Vec::new();
        let mut idx = pos_a;
        loop {
            arc_ab.push(old_face[idx]);
            if idx == pos_b {
                break;
            }
            idx = (idx + 1) % flen;
        }
        let mut arc_ba = Vec::new();
        let mut idx = pos_b;
        loop {
            arc_ba.push(old_face[idx]);
            if idx == pos_a {
                break;
            }
            idx = (idx + 1) % flen;
        }

        // face1 = arc_ab (a..=b) + inner(path).rev()
        let mut face1 = arc_ab;
        for &v in path[1..path.len() - 1].iter().rev() {
            face1.push(v);
        }
        // face2 = arc_ba (b..=a) + inner(path)
        let mut face2 = arc_ba;
        for &v in &path[1..path.len() - 1] {
            face2.push(v);
        }
        faces.push(face1);
        faces.push(face2);

        for &v in &path {
            in_h[v] = true;
        }
        for w in path.windows(2) {
            edge_in_h.insert((w[0].min(w[1]), w[0].max(w[1])));
        }
    }

    // Self-check Euler's formula `V - E + F == 2` on every planar biconnected block!
    if nb + faces.len() != mb + 2 {
        return Ok(BlockPlanarity::NonPlanar {
            kind: "euler_face_identity_failed".to_owned(),
            nodes: verts.to_vec(),
        });
    }

    let global_faces: Vec<Vec<usize>> = faces
        .into_iter()
        .map(|f| f.into_iter().map(|i| verts[i]).collect())
        .collect();
    Ok(BlockPlanarity::Planar(global_faces))
}

fn shortest_path_avoiding_edge(
    src: usize,
    dst: usize,
    adj: &[BTreeSet<usize>],
    forbidden: (usize, usize),
    meter: &mut Meter<'_>,
) -> Result<Option<Vec<usize>>, GraphError> {
    let mut prev: BTreeMap<usize, usize> = BTreeMap::new();
    let mut q = VecDeque::new();
    prev.insert(src, src);
    q.push_back(src);
    while let Some(u) = q.pop_front() {
        meter.tick("dmp_steps")?;
        if u == dst {
            let mut path = vec![dst];
            let mut cur = dst;
            while cur != src {
                cur = prev[&cur];
                path.push(cur);
            }
            path.reverse();
            return Ok(Some(path));
        }
        for &v in &adj[u] {
            if (u.min(v), u.max(v)) == forbidden {
                continue;
            }
            if let std::collections::btree_map::Entry::Vacant(e) = prev.entry(v) {
                e.insert(u);
                q.push_back(v);
            }
        }
    }
    Ok(None)
}

fn path_through_component(
    src: usize,
    dst: usize,
    comp_nodes: &BTreeSet<usize>,
    adj: &[BTreeSet<usize>],
    meter: &mut Meter<'_>,
) -> Result<Option<Vec<usize>>, GraphError> {
    let mut prev: BTreeMap<usize, usize> = BTreeMap::new();
    let mut q = VecDeque::new();
    prev.insert(src, src);
    q.push_back(src);
    while let Some(u) = q.pop_front() {
        meter.tick("dmp_steps")?;
        for &v in &adj[u] {
            if v == dst && u != src {
                let mut path = vec![dst, u];
                let mut cur = u;
                while cur != src {
                    cur = prev[&cur];
                    path.push(cur);
                }
                path.reverse();
                return Ok(Some(path));
            }
            if comp_nodes.contains(&v)
                && let std::collections::btree_map::Entry::Vacant(e) = prev.entry(v)
            {
                e.insert(u);
                q.push_back(v);
            }
        }
    }
    Ok(None)
}

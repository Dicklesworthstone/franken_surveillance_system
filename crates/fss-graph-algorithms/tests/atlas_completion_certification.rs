//! Certification suite for the remaining 8 algorithms of the 27-algorithm Certified Graph Atlas
//! (`fss-esder`, `fss-9mxru`, `fss-8d1g1`, `fss-6gf89`).
#![forbid(unsafe_code)]

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{Rng, TestResult, assert_registered, certify, generate, node_id, registered};
use fss_graph_algorithms::GraphError;
use fss_graph_algorithms::centrality::{self, centrality_family};
use fss_graph_algorithms::community::{self, community_detection};
use fss_graph_algorithms::factorized_join::{
    self, FactorJoinProblem, PatternRelation, factorized_free_join,
};
use fss_graph_algorithms::hits::{self, HitsConfig, SCALE_PPB as HITS_SCALE_PPB, hits};
use fss_graph_algorithms::ppr::{self, PprConfig, SCALE_PPB as PPR_SCALE_PPB, personalized_pagerank};
use fss_graph_algorithms::spectral::{self, SpectralConfig, spectral_change_detection};
use fss_graph_algorithms::steiner::{self, steiner_tree_approximation};
use fss_graph_algorithms::weighted::{Orientation, WeightedGraph, WeightedGraphBuilder};
use fss_graph_algorithms::zset::{
    self, ZSet, ZSetDeltaBatch, ZSetGraphState, zset_equijoin, zset_incremental_equijoin,
    zset_incremental_maintenance,
};

const ATLAS_SEEDS: u64 = 250;

fn emit_log(algorithm_id: &str, cases: u64, status: &str) {
    eprintln!(
        "{{\"suite\":\"atlas_completion_certification\",\"algorithm_id\":\"{algorithm_id}\",\"cases\":{cases},\"status\":\"{status}\"}}"
    );
}

#[test]
fn all_27_graph_algorithms_are_registered_and_implemented() -> TestResult {
    assert_registered(&ppr::IDENTITY)?;
    assert_registered(&hits::IDENTITY)?;
    assert_registered(&centrality::IDENTITY)?;
    assert_registered(&steiner::IDENTITY)?;
    assert_registered(&community::IDENTITY)?;
    assert_registered(&spectral::IDENTITY)?;
    assert_registered(&factorized_join::IDENTITY)?;
    assert_registered(&zset::IDENTITY)?;

    let registry_text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../architecture/graph_algorithms.json"),
    )?;
    let implemented_count = registry_text.matches("\"status\": \"implemented\"").count();
    let specified_count = registry_text.matches("\"status\": \"specified\"").count();
    assert_eq!(
        implemented_count, 27,
        "all 27 registered graph algorithms must have status=implemented"
    );
    assert_eq!(
        specified_count, 0,
        "no registered graph algorithm may remain status=specified"
    );
    emit_log("ALL-27-ATLAS", 27, "certified");
    Ok(())
}

#[test]
fn ppr_certification_and_mass_conservation() -> TestResult {
    let config = PprConfig {
        alpha_ppm: 150_000,
        max_iterations: 20,
        tolerance_ppb: 1_000,
    };
    for seed in 0..ATLAS_SEEDS {
        let spec = generate(seed, Orientation::Directed, 10);
        let g1 = spec.build(None)?;
        let g2 = spec.build(Some(seed ^ 0x55aa_55aa))?;
        let mut rng = Rng(seed ^ 0x1234_5678);

        let mut chosen: BTreeMap<String, u64> = BTreeMap::new();
        if !spec.nodes.is_empty() {
            let k = 1 + rng.below(spec.nodes.len().min(3));
            for _ in 0..k {
                let id = spec.nodes[rng.below(spec.nodes.len())].0.clone();
                let w = 1 + (rng.next() % 10);
                chosen.insert(id, w);
            }
        }
        let seed_vec: Vec<(String, u64)> = chosen.into_iter().collect();
        let mut seed_shuf = seed_vec.clone();
        rng.shuffle(&mut seed_shuf);
        let seeds1: Vec<(&str, u64)> = seed_vec.iter().map(|(s, w)| (s.as_str(), *w)).collect();
        let seeds2: Vec<(&str, u64)> = seed_shuf.iter().map(|(s, w)| (s.as_str(), *w)).collect();

        let b = ppr::bound(
            g1.node_count() as u64,
            g1.arc_count() as u64,
            config.max_iterations,
        );
        let budget = registered(&b);

        let run1 = personalized_pagerank(&g1, &seeds1, &config, budget)?;
        let run2 = personalized_pagerank(&g2, &seeds2, &config, budget)?;
        assert_eq!(run1.output, run2.output);
        assert_eq!(run1.output_digest, run2.output_digest);
        assert_eq!(run1.decision_path_digest, run2.decision_path_digest);

        if g1.node_count() > 0 {
            let total: u64 = run1.output.scores.iter().map(|e| e.score_ppb).sum();
            assert_eq!(total, PPR_SCALE_PPB);
        }
        certify(&run1, &ppr::IDENTITY, &b, |short| {
            personalized_pagerank(&g1, &seeds1, &config, short)
        })?;
    }

    // Fail-closed error checks.
    let mut builder = WeightedGraphBuilder::directed("test-unit");
    builder.add_node("n0").add_node("n1");
    builder.add_arc("n0", "n1", 5);
    let g = builder.build()?;
    let b = registered(&ppr::bound(2, 1, 10));
    let bad_cfg = PprConfig {
        alpha_ppm: 0,
        max_iterations: 10,
        tolerance_ppb: 1_000,
    };
    assert!(matches!(
        personalized_pagerank(&g, &[("n0", 1)], &bad_cfg, b),
        Err(GraphError::PreconditionFailed(_))
    ));
    assert!(matches!(
        personalized_pagerank(&g, &[("missing-node", 1)], &config, b),
        Err(GraphError::UnknownNode(_))
    ));
    emit_log(ppr::IDENTITY.algorithm_id, ATLAS_SEEDS, "certified");
    Ok(())
}

#[test]
fn hits_certification_and_duality() -> TestResult {
    let config = HitsConfig {
        max_iterations: 20,
        tolerance_ppb: 1_000,
    };
    for seed in 0..ATLAS_SEEDS {
        let spec = generate(seed, Orientation::Directed, 10);
        let g1 = spec.build(None)?;
        let g2 = spec.build(Some(seed ^ 0x9988_7766))?;
        let b = hits::bound(
            g1.node_count() as u64,
            g1.arc_count() as u64,
            config.max_iterations,
        );
        let budget = registered(&b);

        let run1 = hits(&g1, &config, budget)?;
        let run2 = hits(&g2, &config, budget)?;
        assert_eq!(run1.output, run2.output);
        assert_eq!(run1.output_digest, run2.output_digest);
        assert_eq!(run1.decision_path_digest, run2.decision_path_digest);

        if g1.node_count() > 0 {
            let hub_sum: u64 = run1.output.hubs.iter().map(|e| e.score_ppb).sum();
            let auth_sum: u64 = run1.output.authorities.iter().map(|e| e.score_ppb).sum();
            assert_eq!(hub_sum, HITS_SCALE_PPB);
            assert_eq!(auth_sum, HITS_SCALE_PPB);
        }
        certify(&run1, &hits::IDENTITY, &b, |short| {
            hits(&g1, &config, short)
        })?;
    }

    // Star graph: n0 -> n1, n0 -> n2, n0 -> n3. Node n0 has all hub mass.
    let mut builder = WeightedGraphBuilder::new(Orientation::Directed, "hits-star");
    for id in ["n0", "n1", "n2", "n3"] {
        builder.add_node(id);
    }
    builder.add_arc("n0", "n1", 10);
    builder.add_arc("n0", "n2", 10);
    builder.add_arc("n0", "n3", 10);
    let star = builder.build()?;
    let b = registered(&hits::bound(4, 3, 15));
    let run = hits(
        &star,
        &HitsConfig {
            max_iterations: 15,
            tolerance_ppb: 1_000,
        },
        b,
    )?;
    let hub_map: BTreeMap<_, _> = run
        .output
        .hubs
        .iter()
        .map(|e| (e.node_id.as_str(), e.score_ppb))
        .collect();
    assert_eq!(hub_map.get("n0").copied(), Some(HITS_SCALE_PPB));
    emit_log(hits::IDENTITY.algorithm_id, ATLAS_SEEDS, "certified");
    Ok(())
}

#[test]
fn centrality_certification_and_reference_oracle() -> TestResult {
    for seed in 0..ATLAS_SEEDS {
        let orientation = if seed % 2 == 0 {
            Orientation::Directed
        } else {
            Orientation::Undirected
        };
        let spec = generate(seed, orientation, 9);
        let g1 = spec.build(None)?;
        let g2 = spec.build(Some(seed ^ 0xabcd_ef01))?;
        let b = centrality::bound(g1.node_count() as u64, g1.arc_count() as u64);
        let budget = registered(&b);

        let run1 = centrality_family(&g1, budget)?;
        let run2 = centrality_family(&g2, budget)?;
        assert_eq!(run1.output, run2.output);
        assert_eq!(run1.output_digest, run2.output_digest);
        assert_eq!(run1.decision_path_digest, run2.decision_path_digest);

        certify(&run1, &centrality::IDENTITY, &b, |short| {
            centrality_family(&g1, short)
        })?;
    }

    // Undirected path: a -- b -- c. Center `b` bridges (a, c) and (c, a), so its betweenness is
    // strictly positive while endpoints `a` and `c` have zero betweenness.
    let mut builder = WeightedGraphBuilder::new(Orientation::Undirected, "path-3");
    for id in ["a", "b", "c"] {
        builder.add_node(id);
    }
    builder.add_arc("a", "b", 5);
    builder.add_arc("b", "c", 5);
    let path = builder.build()?;
    let b = registered(&centrality::bound(3, 2));
    let run = centrality_family(&path, b)?;
    let v_bet: BTreeMap<_, _> = run
        .output
        .vertices
        .iter()
        .map(|v| (v.node_id.as_str(), v.betweenness_ppb))
        .collect();
    assert_eq!(v_bet.get("a").copied(), Some(0));
    assert_eq!(v_bet.get("c").copied(), Some(0));
    assert_eq!(v_bet.get("b").copied(), Some(centrality::SCALE_PPB));
    emit_log(centrality::IDENTITY.algorithm_id, ATLAS_SEEDS, "certified");
    Ok(())
}

/// Exact brute-force Steiner tree oracle for small undirected graphs (`n <= 8`).
fn exact_steiner_oracle(g: &WeightedGraph, terminals: &[&str]) -> Option<u64> {
    let term_set: BTreeSet<&str> = terminals.iter().copied().collect();
    if term_set.len() <= 1 {
        return Some(0);
    }
    let n = g.node_count();
    let mut term_mask = 0_usize;
    for (idx, id) in g.ids().iter().enumerate() {
        if term_set.contains(id.as_str()) {
            term_mask |= 1 << idx;
        }
    }
    let mut best: Option<u64> = None;
    for mask in 1..(1_usize << n) {
        if (mask & term_mask) != term_mask {
            continue;
        }
        let first = mask.trailing_zeros() as usize;
        let mut visited = 1_usize << first;
        let mut total_w = 0_u64;
        loop {
            if visited == mask {
                best = Some(best.map_or(total_w, |b| b.min(total_w)));
                break;
            }
            let mut min_edge: Option<(usize, u64)> = None;
            for u in 0..n {
                if (visited & (1 << u)) == 0 {
                    continue;
                }
                for &arc_idx in g.out_arcs(u as u32) {
                    let arc = g.arc(arc_idx);
                    let v = arc.other(u as u32) as usize;
                    if (mask & (1 << v)) != 0 && (visited & (1 << v)) == 0 {
                        if min_edge.is_none_or(|(_, w)| arc.weight < w) {
                            min_edge = Some((v, arc.weight));
                        }
                    }
                }
            }
            match min_edge {
                Some((v, w)) => {
                    visited |= 1 << v;
                    total_w += w;
                }
                None => break,
            }
        }
    }
    best
}

#[test]
fn steiner_tree_certification_and_exact_subset_oracle() -> TestResult {
    for seed in 0..ATLAS_SEEDS {
        let spec = generate(seed, Orientation::Undirected, 7);
        let g1 = spec.build(None)?;
        let g2 = spec.build(Some(seed ^ 0x3141_5926))?;
        let mut rng = Rng(seed ^ 0x2718_2818);
        let mut chosen: BTreeSet<String> = BTreeSet::new();
        if !spec.nodes.is_empty() {
            let k = rng.below(spec.nodes.len().min(4) + 1);
            for _ in 0..k {
                chosen.insert(spec.nodes[rng.below(spec.nodes.len())].0.clone());
            }
        }
        let term_strings: Vec<String> = chosen.into_iter().collect();
        let mut term_shuf = term_strings.clone();
        rng.shuffle(&mut term_shuf);
        let terms1: Vec<&str> = term_strings.iter().map(String::as_str).collect();
        let terms2: Vec<&str> = term_shuf.iter().map(String::as_str).collect();

        let b = steiner::bound(
            g1.node_count() as u64,
            g1.arc_count() as u64,
            terms1.len() as u64,
        );
        let budget = registered(&b);

        let oracle_opt = exact_steiner_oracle(&g1, &terms1);
        let res1 = steiner_tree_approximation(&g1, &terms1, budget);
        let res2 = steiner_tree_approximation(&g2, &terms2, budget);

        match oracle_opt {
            None => {
                assert!(matches!(res1, Err(GraphError::PreconditionFailed(_))));
                assert!(matches!(res2, Err(GraphError::PreconditionFailed(_))));
            }
            Some(opt) => {
                let run1 = res1?;
                let run2 = res2?;
                assert_eq!(run1.output, run2.output);
                assert_eq!(run1.output_digest, run2.output_digest);
                assert_eq!(run1.decision_path_digest, run2.decision_path_digest);
                assert!(
                    run1.output.total_weight >= opt,
                    "Steiner tree weight {} cannot be less than optimal {}",
                    run1.output.total_weight,
                    opt
                );
                assert!(
                    run1.output.total_weight <= opt.saturating_mul(2),
                    "KMB 2-approximation violated: got {} > 2 * {}",
                    run1.output.total_weight,
                    opt
                );
                certify(&run1, &steiner::IDENTITY, &b, |short| {
                    steiner_tree_approximation(&g1, &terms1, short)
                })?;
            }
        }
    }
    emit_log(steiner::IDENTITY.algorithm_id, ATLAS_SEEDS, "certified");
    Ok(())
}

#[test]
fn community_modularity_certification_and_monotonicity() -> TestResult {
    for seed in 0..ATLAS_SEEDS {
        let spec = generate(seed, Orientation::Undirected, 10);
        let g1 = spec.build(None)?;
        let g2 = spec.build(Some(seed ^ 0xdead_c0de))?;
        let max_passes = 8_u32;
        let b = community::bound(g1.node_count() as u64, g1.arc_count() as u64, max_passes);
        let budget = registered(&b);

        let run1 = community_detection(&g1, max_passes, budget)?;
        let run2 = community_detection(&g2, max_passes, budget)?;
        assert_eq!(run1.output, run2.output);
        assert_eq!(run1.output_digest, run2.output_digest);
        assert_eq!(run1.decision_path_digest, run2.decision_path_digest);

        certify(&run1, &community::IDENTITY, &b, |short| {
            community_detection(&g1, max_passes, short)
        })?;
    }

    // Two planted triangles connected by a weak bridge.
    let mut builder = WeightedGraphBuilder::new(Orientation::Undirected, "two-triangles");
    for id in ["a0", "a1", "a2", "b0", "b1", "b2"] {
        builder.add_node(id);
    }
    for (u, v) in [("a0", "a1"), ("a1", "a2"), ("a0", "a2")] {
        builder.add_arc(u, v, 50);
    }
    for (u, v) in [("b0", "b1"), ("b1", "b2"), ("b0", "b2")] {
        builder.add_arc(u, v, 50);
    }
    builder.add_arc("a2", "b0", 1);
    let g = builder.build()?;
    let b = registered(&community::bound(6, 7, 10));
    let run = community_detection(&g, 10, b)?;
    assert_eq!(run.output.communities.len(), 2);
    assert!(run.output.modularity_ppb > 0);
    emit_log(community::IDENTITY.algorithm_id, ATLAS_SEEDS, "certified");
    Ok(())
}

#[test]
fn spectral_fiedler_certification_and_dumbbell_cut() -> TestResult {
    let config = SpectralConfig {
        max_iterations: 25,
        tolerance_ppb: 1_000,
        reference_lambda2_ppb: Some(250_000_000),
    };
    for seed in 0..ATLAS_SEEDS {
        let spec = generate(seed, Orientation::Undirected, 10);
        let g1 = spec.build(None)?;
        let g2 = spec.build(Some(seed ^ 0xfeed_face))?;
        let b = spectral::bound(
            g1.node_count() as u64,
            g1.arc_count() as u64,
            config.max_iterations,
        );
        let budget = registered(&b);

        let run1 = spectral_change_detection(&g1, &config, budget)?;
        let run2 = spectral_change_detection(&g2, &config, budget)?;
        assert_eq!(run1.output, run2.output);
        assert_eq!(run1.output_digest, run2.output_digest);
        assert_eq!(run1.decision_path_digest, run2.decision_path_digest);

        certify(&run1, &spectral::IDENTITY, &b, |short| {
            spectral_change_detection(&g1, &config, short)
        })?;
    }

    // Dumbbell graph: clique A (a0, a1, a2) and clique B (b0, b1, b2) connected by bridge (a2, b0).
    let mut builder = WeightedGraphBuilder::new(Orientation::Undirected, "dumbbell");
    for id in ["a0", "a1", "a2", "b0", "b1", "b2"] {
        builder.add_node(id);
    }
    for (u, v) in [("a0", "a1"), ("a1", "a2"), ("a0", "a2")] {
        builder.add_arc(u, v, 100);
    }
    for (u, v) in [("b0", "b1"), ("b1", "b2"), ("b0", "b2")] {
        builder.add_arc(u, v, 100);
    }
    builder.add_arc("a2", "b0", 1);
    let g = builder.build()?;
    let b = registered(&spectral::bound(6, 7, 40));
    let run = spectral_change_detection(
        &g,
        &SpectralConfig {
            max_iterations: 40,
            tolerance_ppb: 100,
            reference_lambda2_ppb: None,
        },
        b,
    )?;
    let coords: BTreeMap<_, _> = run
        .output
        .eigenvector
        .iter()
        .map(|e| (e.node_id.as_str(), e.value_ppb))
        .collect();
    let sign_a = coords["a0"].signum();
    let sign_b = coords["b0"].signum();
    assert_ne!(sign_a, 0);
    assert_eq!(sign_a, -sign_b, "two cliques must have opposite Fiedler signs");
    emit_log(spectral::IDENTITY.algorithm_id, ATLAS_SEEDS, "certified");
    Ok(())
}

#[test]
fn factorized_free_join_certification_and_natural_join_oracle() -> TestResult {
    for seed in 0..150_u64 {
        let mut rng = Rng(seed ^ 0x7777_8888);
        let mut dom_set: BTreeSet<String> = BTreeSet::new();
        let dom_size = 1 + rng.below(6);
        for i in 0..dom_size {
            dom_set.insert(node_id(i));
        }
        let domain: Vec<String> = dom_set.into_iter().collect();
        let vars = vec!["v0".to_owned(), "v1".to_owned(), "v2".to_owned()];

        let make_pairs = |rng: &mut Rng| -> Vec<(String, String)> {
            let mut out = Vec::new();
            for a in &domain {
                for b in &domain {
                    if rng.chance(450) {
                        out.push((a.clone(), b.clone()));
                    }
                }
            }
            out.sort();
            out.dedup();
            out
        };

        let pairs01 = make_pairs(&mut rng);
        let pairs12 = make_pairs(&mut rng);
        let pairs02 = make_pairs(&mut rng);

        let prob = FactorJoinProblem {
            variables: vars,
            domain: domain.clone(),
            relations: vec![
                PatternRelation {
                    name: "R01".to_owned(),
                    left_var: 0,
                    right_var: 1,
                    pairs: pairs01.clone(),
                },
                PatternRelation {
                    name: "R12".to_owned(),
                    left_var: 1,
                    right_var: 2,
                    pairs: pairs12.clone(),
                },
                PatternRelation {
                    name: "R02".to_owned(),
                    left_var: 0,
                    right_var: 2,
                    pairs: pairs02.clone(),
                },
            ],
        };

        let m_count = (pairs01.len() + pairs12.len() + pairs02.len()) as u64;
        let b = factorized_join::bound(domain.len() as u64, m_count, 3);
        let budget = registered(&b);

        let run = factorized_free_join(&prob, budget)?;

        if !run.output.capped {
            let set01: BTreeSet<_> = pairs01.into_iter().collect();
            let set12: BTreeSet<_> = pairs12.into_iter().collect();
            let set02: BTreeSet<_> = pairs02.into_iter().collect();
            let mut expected: BTreeSet<Vec<String>> = BTreeSet::new();
            for x in &domain {
                for y in &domain {
                    if !set01.contains(&(x.clone(), y.clone())) {
                        continue;
                    }
                    for z in &domain {
                        if set12.contains(&(y.clone(), z.clone()))
                            && set02.contains(&(x.clone(), z.clone()))
                        {
                            expected.insert(vec![x.clone(), y.clone(), z.clone()]);
                        }
                    }
                }
            }
            let actual: BTreeSet<Vec<String>> =
                run.output.materialize_tuples(3).into_iter().collect();
            assert_eq!(actual, expected);
        }

        certify(&run, &factorized_join::IDENTITY, &b, |short| {
            factorized_free_join(&prob, short)
        })?;
    }
    emit_log(factorized_join::IDENTITY.algorithm_id, 150, "certified");
    Ok(())
}

#[test]
fn zset_incremental_view_certification_and_abelian_group_laws() -> TestResult {
    // Verify Abelian group and bilinear join laws first.
    let a = ZSet::from_iter_checked([("k1".to_owned(), 2), ("k2".to_owned(), -1)])?;
    let b = ZSet::from_iter_checked([("k1".to_owned(), -2), ("k3".to_owned(), 4)])?;
    let c = ZSet::from_iter_checked([("k2".to_owned(), 5), ("k3".to_owned(), -1)])?;
    assert_eq!(a.add(&b)?, b.add(&a)?);
    assert_eq!(a.add(&b)?.add(&c)?, a.add(&b.add(&c)?)?);
    assert!(a.add(&a.negate()?)?.is_empty());

    for seed in 0..150_u64 {
        let mut rng = Rng(seed ^ 0x4242_4242);
        let nodes = ["n0", "n1", "n2", "n3"];
        let sample_arcs = |rng: &mut Rng, count: usize| -> Vec<((String, String), i64)> {
            let mut out = Vec::new();
            for _ in 0..count {
                let u = nodes[rng.below(nodes.len())].to_owned();
                let v = nodes[rng.below(nodes.len())].to_owned();
                let w = (rng.below(5) as i64) - 2;
                out.push(((u, v), w));
            }
            out
        };

        let base_count = rng.below(6);
        let base_arcs = ZSet::from_iter_checked(sample_arcs(&mut rng, base_count))?;
        let base_nodes = ZSet::from_iter_checked(nodes.iter().map(|&n| (n.to_owned(), 1_i64)))?;
        let delta_count = rng.below(5);
        let arc_deltas = sample_arcs(&mut rng, delta_count);
        let node_deltas = vec![(nodes[rng.below(nodes.len())].to_owned(), 1_i64)];

        let delta_arcs_zset = ZSet::from_iter_checked(arc_deltas.clone())?;
        let next_arcs = base_arcs.add(&delta_arcs_zset)?;

        // Verify bilinear DBSP equijoin identity:
        // Q(E + dE, E + dE) - Q(E, E) == dE join E + E join dE + dE join dE
        let full_before = zset_equijoin(&base_arcs, &base_arcs)?;
        let full_after = zset_equijoin(&next_arcs, &next_arcs)?;
        let expected_join_delta = full_after.subtract(&full_before)?;
        let actual_join_delta =
            zset_incremental_equijoin(&base_arcs, &delta_arcs_zset, &base_arcs, &delta_arcs_zset)?;
        assert_eq!(actual_join_delta, expected_join_delta);

        let state = ZSetGraphState {
            nodes: base_nodes.clone(),
            arcs: base_arcs.clone(),
        };
        let batch = ZSetDeltaBatch {
            commit_sequence: seed + 1,
            node_deltas: node_deltas.clone(),
            arc_deltas: arc_deltas.clone(),
        };

        let next_nodes = base_nodes.add(&ZSet::from_iter_checked(node_deltas)?)?;
        let v_count = next_nodes.len().max(base_nodes.len()) as u64;
        let e_count = next_arcs.len().max(base_arcs.len()) as u64;
        let d_count = (batch.node_deltas.len() + batch.arc_deltas.len()) as u64;
        let bnd = zset::bound(v_count, e_count, d_count);
        let budget = registered(&bnd);

        let run = zset_incremental_maintenance(&state, &batch, budget)?;
        certify(&run, &zset::IDENTITY, &bnd, |short| {
            zset_incremental_maintenance(&state, &batch, short)
        })?;
    }
    emit_log(zset::IDENTITY.algorithm_id, 150, "certified");
    Ok(())
}

#![forbid(unsafe_code)]
//! `ALG-FACILITY-001` — Facility location, k-center, and p-median optimization (`fss-x4a.23.70.1`).
//!
//! Keeps three distinct placement objectives strictly separate (never equating them to set cover):
//! - [`FacilityObjective::FacilityLocation`]: minimize `sum(opening_cost) + sum(demand_weight * dist)`;
//! - [`FacilityObjective::KCenter`]: minimize worst-case service radius `max_d min_{f in S} dist(f, d)`;
//! - [`FacilityObjective::PMedian`]: minimize total weighted service distance `sum_d w(d) * min_{f in S} dist(f, d)`.
//!
//! Enforces facility capacity caps, privacy exclusions, and failure-domain diversity. Runs exact
//! exhaustive search for bounded small instances (`candidates <= 16 && k <= 6`), and deterministic
//! greedy + single-swap heuristic with explicit measured regret/stop reason otherwise. Budget
//! exhaustion fails closed (`GraphError::BudgetExhausted`) — never silently returning a partial
//! optimum.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, mul, query_digest, query_encoder,
};
use crate::graph::GraphError;

/// Projection digest domain (`SCHEMA-DOMAIN-GRAPH-FACILITY-PROJECTION-001`).
pub const PROJECTION_DOMAIN: &str = "fss.graph.facility_projection.v1";
/// Output digest domain (`SCHEMA-DOMAIN-GRAPH-FACILITY-OUTPUT-001`).
pub const OUTPUT_DOMAIN: &str = "fss.graph.facility_output.v1";
/// Decision-path digest domain (`SCHEMA-DOMAIN-GRAPH-FACILITY-DECISION-PATH-001`).
pub const DECISION_PATH_DOMAIN: &str = "fss.graph.facility_decision_path.v1";

/// Registered identity (`architecture/graph_algorithms.json`, `ALG-FACILITY-001`).
pub static IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-FACILITY-001",
    algorithm_name: "facility_location_k_center_p_median",
    tie_break_rule: "canonical objective then lexicographic facility identity tuple",
    complexity_witness: "subset evaluations, distance lookups, and greedy swap scans",
    output_size_witness: "<= k selected facilities plus |D| demand assignments",
    exactness: "bounded_exact_or_approximate",
    implementation_id: "fss-graph-algorithms:alg-facility-001:exact-small-and-greedy-swap:v1",
    tie_break_policy_id: "tie:min-objective-then-lexicographic-facility-id-tuple:v1",
    policy_id: "graph-policy:facility-placement:distinct-fl-kcenter-pmedian:capacity-privacy-domain-constraints:tie:min-objective-then-lexicographic-facility-id-tuple:v1",
    complexity_bound_id: "bound:alg-facility-001:exact-comb-or-greedy-swap-polynomial:v1",
    output_domain: OUTPUT_DOMAIN,
    decision_path_domain: DECISION_PATH_DOMAIN,
};

/// Maximum candidate facilities eligible for exhaustive exact combination search.
pub const EXACT_CANDIDATE_LIMIT: usize = 16;
/// Maximum `k` eligible for exhaustive exact combination search.
pub const EXACT_K_LIMIT: usize = 6;

/// Distinct placement objective — NEVER collapsed into set cover!
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FacilityObjective {
    /// Minimize `sum_{f in S} opening_cost(f) + sum_{d in D} weight(d) * dist(assign(d), d)`.
    FacilityLocation,
    /// Minimize worst-case weighted distance `max_{d in D} dist(assign(d), d)`.
    KCenter,
    /// Minimize total weighted service distance `sum_{d in D} weight(d) * dist(assign(d), d)`.
    PMedian,
}

impl FacilityObjective {
    /// Stable canonical tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FacilityLocation => "facility_location",
            Self::KCenter => "k_center",
            Self::PMedian => "p_median",
        }
    }
}

/// One candidate camera/compute/cache/viewpoint facility site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FacilityCandidate {
    /// Stable facility identifier.
    pub facility_id: String,
    /// Opening/installation cost (exact integer units).
    pub opening_cost: u64,
    /// Maximum demand weight/count this facility can serve (`>= 1`).
    pub capacity: u64,
    /// Shared infrastructure failure domain (e.g., `power:circuit-a`).
    pub failure_domain: String,
    /// True iff privacy policy forbids placing a sensor/cache here.
    pub privacy_excluded: bool,
}

/// One spatial zone, viewpoint, or workload demand point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DemandPoint {
    /// Stable demand point identifier.
    pub demand_id: String,
    /// Positive importance/load weight (`>= 1`).
    pub weight: u64,
}

/// Canonical facility-placement problem instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FacilityProblem {
    /// Placement objective (`FacilityLocation`, `KCenter`, or `PMedian`).
    pub objective: FacilityObjective,
    /// Maximum facilities to select (`>= 1`).
    pub max_facilities: usize,
    /// Minimum distinct failure domains required across selected facilities (`0` disables).
    pub min_distinct_failure_domains: usize,
    /// Candidate facilities.
    pub candidates: Vec<FacilityCandidate>,
    /// Demand points to cover/serve.
    pub demands: Vec<DemandPoint>,
    /// Exact integer distance/cost from `(facility_id, demand_id)` (`None` => unreachable).
    pub distances: BTreeMap<(String, String), u64>,
}

impl FacilityProblem {
    /// Validates and computes a canonical insertion-order-independent projection digest.
    pub fn projection_digest(&self) -> Result<ContentDigest, GraphError> {
        if self.max_facilities == 0 || self.demands.is_empty() || self.candidates.is_empty() {
            return Err(GraphError::PreconditionFailed(
                "facility problem requires max_facilities >= 1, >= 1 candidate, and >= 1 demand"
                    .to_owned(),
            ));
        }
        let mut cands = self.candidates.clone();
        cands.sort_by(|a, b| a.facility_id.cmp(&b.facility_id));
        for pair in cands.windows(2) {
            if pair[0].facility_id == pair[1].facility_id {
                return Err(GraphError::PreconditionFailed(
                    "duplicate facility_id".to_owned(),
                ));
            }
        }
        for c in &cands {
            if c.facility_id.is_empty() || c.failure_domain.is_empty() || c.capacity == 0 {
                return Err(GraphError::PreconditionFailed(
                    "invalid facility candidate fields".to_owned(),
                ));
            }
        }
        let mut dems = self.demands.clone();
        dems.sort_by(|a, b| a.demand_id.cmp(&b.demand_id));
        for pair in dems.windows(2) {
            if pair[0].demand_id == pair[1].demand_id {
                return Err(GraphError::PreconditionFailed(
                    "duplicate demand_id".to_owned(),
                ));
            }
        }
        for d in &dems {
            if d.demand_id.is_empty() || d.weight == 0 {
                return Err(GraphError::PreconditionFailed(
                    "invalid demand point fields".to_owned(),
                ));
            }
        }
        let mut enc = CanonicalEncoder::new();
        enc.text(PROJECTION_DOMAIN);
        enc.text(self.objective.as_str());
        enc.u64(self.max_facilities as u64);
        enc.u64(self.min_distinct_failure_domains as u64);
        enc.u64(cands.len() as u64);
        for c in &cands {
            enc.text(&c.facility_id);
            enc.u64(c.opening_cost);
            enc.u64(c.capacity);
            enc.text(&c.failure_domain);
            enc.u8(u8::from(c.privacy_excluded));
        }
        enc.u64(dems.len() as u64);
        for d in &dems {
            enc.text(&d.demand_id);
            enc.u64(d.weight);
        }
        enc.u64(self.distances.len() as u64);
        for ((f, d), dist) in &self.distances {
            enc.text(f);
            enc.text(d);
            enc.u64(*dist);
        }
        Ok(ContentDigest::sha256(&enc.finish()))
    }
}

/// Exactness / lane label emitted with every facility optimization output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FacilitySolverLane {
    /// Exhaustive exact optimum over all valid subsets up to `max_facilities`.
    ExactSmall,
    /// Deterministic greedy construction + 1-swap local search with regret upper bound.
    ApproximateGreedySwap,
}

/// Assignment of one demand point to a selected facility.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DemandAssignment {
    /// Demand identifier.
    pub demand_id: String,
    /// Serving facility identifier.
    pub facility_id: String,
    /// Distance from serving facility to demand.
    pub distance: u64,
}

/// Canonical answer of `ALG-FACILITY-001`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FacilityPlacementResult {
    /// Objective optimized.
    pub objective: FacilityObjective,
    /// Exact or heuristic lane executed.
    pub lane: FacilitySolverLane,
    /// True iff a feasible assignment satisfying capacity, privacy, and failure-domain diversity exists.
    pub feasible: bool,
    /// Selected facility identifiers in sorted canonical order.
    pub selected_facilities: Vec<String>,
    /// Assignment of every demand point (sorted by `demand_id`).
    pub assignments: Vec<DemandAssignment>,
    /// Exact integer objective value (`u64::MAX` if infeasible).
    pub objective_value: u64,
    /// Distinct failure domains represented by `selected_facilities`.
    pub distinct_failure_domains: usize,
    /// Conservative upper bound on regret relative to an unconstrained per-demand lower bound.
    pub regret_upper_bound: u64,
    /// Always `false`: placement advice NEVER authorizes deployment or effects.
    pub grants_effect_authority: bool,
}

impl CertifiedOutput for FacilityPlacementResult {
    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(self.objective.as_str());
        encoder.u8(match self.lane {
            FacilitySolverLane::ExactSmall => 1,
            FacilitySolverLane::ApproximateGreedySwap => 2,
        });
        encoder.u8(u8::from(self.feasible));
        encoder.u64(self.objective_value);
        encoder.u64(self.distinct_failure_domains as u64);
        encoder.u64(self.regret_upper_bound);
        encoder.u64(self.selected_facilities.len() as u64);
        for f in &self.selected_facilities {
            encoder.text(f);
        }
        encoder.u64(self.assignments.len() as u64);
        for a in &self.assignments {
            encoder.text(&a.demand_id);
            encoder.text(&a.facility_id);
            encoder.u64(a.distance);
        }
    }

    fn entries(&self) -> u64 {
        (self.selected_facilities.len() + self.assignments.len()) as u64
    }
}

fn comb_upper(n: u64, k: u64) -> u64 {
    let mut sum = 1_u64;
    let mut cur = 1_u64;
    let lim = k.min(n);
    for i in 1..=lim {
        cur = cur.saturating_mul(n.saturating_sub(i - 1)) / i;
        sum = sum.saturating_add(cur);
    }
    sum
}

/// Registered complexity bound for `c` eligible candidates, `d` demands, and `k` max facilities.
#[must_use]
pub fn bound(c: u64, d: u64, k: u64) -> Vec<BoundRow> {
    let exact_evals = if c <= EXACT_CANDIDATE_LIMIT as u64 && k <= EXACT_K_LIMIT as u64 {
        comb_upper(c, k)
    } else {
        add(mul(k, c), mul(mul(k, c), 2))
    };
    let eval_cap = exact_evals.max(1);
    vec![
        ("subset_evaluations", add(eval_cap, c)),
        ("distance_lookups", add(mul(eval_cap, mul(d, k.max(1))), d)),
        (OUTPUT_ENTRIES, add(k, d)),
    ]
}

/// Evaluates one candidate facility subset under exact capacity/diversity constraints.
fn evaluate_subset(
    subset: &[usize],
    eligible: &[FacilityCandidate],
    demands: &[DemandPoint],
    distances: &BTreeMap<(String, String), u64>,
    objective: FacilityObjective,
    min_domains: usize,
    meter: &mut Meter<'_>,
) -> Result<Option<(u64, usize, Vec<DemandAssignment>)>, GraphError> {
    meter.tick("subset_evaluations")?;
    if subset.is_empty() {
        return Ok(None);
    }
    let mut domains = BTreeSet::new();
    let mut opening_sum = 0_u64;
    let mut rem_cap: Vec<u64> = Vec::with_capacity(subset.len());
    for &idx in subset {
        let c = &eligible[idx];
        domains.insert(c.failure_domain.as_str());
        opening_sum = opening_sum
            .checked_add(c.opening_cost)
            .ok_or(GraphError::ArithmeticOverflow("opening_cost"))?;
        rem_cap.push(c.capacity);
    }
    if domains.len() < min_domains {
        return Ok(None);
    }

    // Assign demands in deterministic order of descending weight then ascending demand_id so
    // heavy demands get priority for scarce capacity deterministically.
    let mut dem_order: Vec<usize> = (0..demands.len()).collect();
    dem_order.sort_by(|&a, &b| {
        demands[b]
            .weight
            .cmp(&demands[a].weight)
            .then_with(|| demands[a].demand_id.cmp(&demands[b].demand_id))
    });

    let mut assignments = Vec::with_capacity(demands.len());
    let mut total_weighted_dist = 0_u64;
    let mut max_dist = 0_u64;

    for d_idx in dem_order {
        let dem = &demands[d_idx];
        let mut best: Option<(u64, usize)> = None;
        for (slot, &f_idx) in subset.iter().enumerate() {
            meter.tick("distance_lookups")?;
            if rem_cap[slot] < dem.weight {
                continue;
            }
            if let Some(&dist) =
                distances.get(&(eligible[f_idx].facility_id.clone(), dem.demand_id.clone()))
            {
                let cand_key = (dist, slot);
                if best.is_none_or(|b| cand_key < b) {
                    best = Some(cand_key);
                }
            }
        }
        let Some((dist, slot)) = best else {
            return Ok(None);
        };
        rem_cap[slot] -= dem.weight;
        max_dist = max_dist.max(dist);
        let weighted = dist
            .checked_mul(dem.weight)
            .ok_or(GraphError::ArithmeticOverflow("weighted_distance"))?;
        total_weighted_dist = total_weighted_dist
            .checked_add(weighted)
            .ok_or(GraphError::ArithmeticOverflow("total_weighted_distance"))?;
        assignments.push(DemandAssignment {
            demand_id: dem.demand_id.clone(),
            facility_id: eligible[subset[slot]].facility_id.clone(),
            distance: dist,
        });
    }
    assignments.sort_by(|a, b| a.demand_id.cmp(&b.demand_id));

    let obj = match objective {
        FacilityObjective::FacilityLocation => opening_sum
            .checked_add(total_weighted_dist)
            .ok_or(GraphError::ArithmeticOverflow("facility_location_obj"))?,
        FacilityObjective::KCenter => max_dist,
        FacilityObjective::PMedian => total_weighted_dist,
    };
    Ok(Some((obj, domains.len(), assignments)))
}

/// Runs `ALG-FACILITY-001` over `problem` under declared `budget` and cooperative cancellation.
pub fn solve_facility_placement(
    problem: &FacilityProblem,
    budget: Budget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<CertifiedRun<FacilityPlacementResult>, GraphError> {
    let proj_digest = problem.projection_digest()?;
    let mut eligible: Vec<FacilityCandidate> = problem
        .candidates
        .iter()
        .filter(|c| !c.privacy_excluded)
        .cloned()
        .collect();
    eligible.sort_by(|a, b| a.facility_id.cmp(&b.facility_id));
    let mut demands = problem.demands.clone();
    demands.sort_by(|a, b| a.demand_id.cmp(&b.demand_id));

    let k = problem.max_facilities.min(eligible.len());
    let bound_rows = bound(eligible.len() as u64, demands.len() as u64, k as u64);
    let mut meter = Meter::new_cancellable(&IDENTITY, budget, is_cancelled);

    let mut q = query_encoder(&IDENTITY, proj_digest);
    q.text(problem.objective.as_str());
    q.u64(problem.max_facilities as u64);
    q.u64(problem.min_distinct_failure_domains as u64);
    let input_digest = query_digest(q);

    // Compute an unconstrained per-demand optimistic lower bound for honest regret measurement.
    let mut optimistic_lb = 0_u64;
    for dem in &demands {
        let min_d = eligible
            .iter()
            .filter_map(|c| {
                problem
                    .distances
                    .get(&(c.facility_id.clone(), dem.demand_id.clone()))
                    .copied()
            })
            .min()
            .unwrap_or(0);
        match problem.objective {
            FacilityObjective::KCenter => optimistic_lb = optimistic_lb.max(min_d),
            FacilityObjective::PMedian | FacilityObjective::FacilityLocation => {
                optimistic_lb = optimistic_lb.saturating_add(min_d.saturating_mul(dem.weight));
            }
        }
    }

    let use_exact = eligible.len() <= EXACT_CANDIDATE_LIMIT && k <= EXACT_K_LIMIT;
    let lane = if use_exact {
        FacilitySolverLane::ExactSmall
    } else {
        FacilitySolverLane::ApproximateGreedySwap
    };

    let mut best_sol: Option<(u64, Vec<usize>, usize, Vec<DemandAssignment>)> = None;

    if k > 0 && use_exact {
        // Exhaustive subset enumeration for sizes 1..=k in canonical lexicographic order.
        let mut cur = Vec::with_capacity(k);
        for target_size in 1..=k {
            enumerate_subsets(
                0,
                target_size,
                &mut cur,
                &eligible,
                &demands,
                &problem.distances,
                problem.objective,
                problem.min_distinct_failure_domains,
                &mut meter,
                &mut best_sol,
            )?;
        }
    } else if k > 0 {
        // Deterministic greedy selection + 1-swap local search for large instances.
        let mut chosen: Vec<usize> = Vec::new();
        for _ in 0..k {
            let mut step_best: Option<(u64, usize, usize, Vec<DemandAssignment>)> = None;
            let mut cur_domains: BTreeSet<&str> = chosen
                .iter()
                .map(|&i| eligible[i].failure_domain.as_str())
                .collect();
            let mut fallback_cand: Option<(usize, u64, u64, usize)> = None;
            for cand in 0..eligible.len() {
                if chosen.contains(&cand) {
                    continue;
                }
                let mut trial = chosen.clone();
                trial.push(cand);
                trial.sort_unstable();
                // During greedy ramp-up allow domain count to grow toward min_distinct_failure_domains.
                let min_d = if trial.len() >= problem.min_distinct_failure_domains {
                    problem.min_distinct_failure_domains
                } else {
                    0
                };
                if let Some((obj, doms, assigns)) = evaluate_subset(
                    &trial,
                    &eligible,
                    &demands,
                    &problem.distances,
                    problem.objective,
                    min_d,
                    &mut meter,
                )? && step_best.as_ref().is_none_or(|b| (obj, cand) < (b.0, b.1))
                {
                    step_best = Some((obj, cand, doms, assigns));
                } else if step_best.is_none() {
                    // When capacity or reachability requires >1 facility, pick the best capacity +
                    // failure-domain coverage contributor so ramp-up reaches a feasible subset!
                    let new_dom = usize::from(
                        cur_domains.len() < problem.min_distinct_failure_domains
                            && !cur_domains.contains(eligible[cand].failure_domain.as_str()),
                    );
                    let reachable_weight: u64 = demands
                        .iter()
                        .filter(|d| {
                            problem.distances.contains_key(&(
                                eligible[cand].facility_id.clone(),
                                d.demand_id.clone(),
                            ))
                        })
                        .map(|d| d.weight)
                        .sum();
                    let effective_cap = eligible[cand].capacity.min(reachable_weight);
                    let key = (new_dom, effective_cap, reachable_weight, cand);
                    let better = match fallback_cand {
                        None => true,
                        Some((bd, bc, br, bi)) => {
                            (key.0, key.1, key.2) > (bd, bc, br)
                                || ((key.0, key.1, key.2) == (bd, bc, br) && key.3 < bi)
                        }
                    };
                    if better {
                        fallback_cand = Some(key);
                    }
                }
            }
            if let Some((obj, cand, doms, assigns)) = step_best {
                cur_domains.insert(eligible[cand].failure_domain.as_str());
                chosen.push(cand);
                chosen.sort_unstable();
                if doms >= problem.min_distinct_failure_domains
                    && best_sol
                        .as_ref()
                        .is_none_or(|b| (obj, chosen.as_slice()) < (b.0, b.1.as_slice()))
                {
                    best_sol = Some((obj, chosen.clone(), doms, assigns));
                }
            } else if let Some((_, _, _, cand)) = fallback_cand {
                chosen.push(cand);
                chosen.sort_unstable();
            } else {
                break;
            }
        }
        // Single deterministic 1-swap improvement pass.
        if let Some((mut cur_obj, mut cur_set, _, _)) = best_sol.clone() {
            for pos in 0..cur_set.len() {
                for cand in 0..eligible.len() {
                    if cur_set.contains(&cand) {
                        continue;
                    }
                    let mut trial = cur_set.clone();
                    trial[pos] = cand;
                    trial.sort_unstable();
                    if let Some((obj, doms, assigns)) = evaluate_subset(
                        &trial,
                        &eligible,
                        &demands,
                        &problem.distances,
                        problem.objective,
                        problem.min_distinct_failure_domains,
                        &mut meter,
                    )? && (obj, trial.as_slice()) < (cur_obj, cur_set.as_slice())
                    {
                        cur_obj = obj;
                        cur_set = trial.clone();
                        best_sol = Some((obj, trial, doms, assigns));
                    }
                }
            }
        }
    }

    let output = match best_sol {
        Some((obj, subset, doms, assignments)) => {
            let selected_facilities: Vec<String> = subset
                .iter()
                .map(|&i| eligible[i].facility_id.clone())
                .collect();
            for f in &selected_facilities {
                meter.path().text(f);
            }
            let regret_upper_bound = if lane == FacilitySolverLane::ExactSmall {
                0
            } else {
                obj.saturating_sub(optimistic_lb)
            };
            FacilityPlacementResult {
                objective: problem.objective,
                lane,
                feasible: true,
                selected_facilities,
                assignments,
                objective_value: obj,
                distinct_failure_domains: doms,
                regret_upper_bound,
                grants_effect_authority: false,
            }
        }
        None => FacilityPlacementResult {
            objective: problem.objective,
            lane,
            feasible: false,
            selected_facilities: Vec::new(),
            assignments: Vec::new(),
            objective_value: u64::MAX,
            distinct_failure_domains: 0,
            regret_upper_bound: 0,
            grants_effect_authority: false,
        },
    };

    let shape = InputShape {
        node_count: (eligible.len() + demands.len()) as u64,
        edge_count: problem.distances.len() as u64,
        input_digest,
    };
    let peak_bytes = ((eligible.len() + demands.len() + 1) * 128) as u64;
    meter.finish(&IDENTITY, shape, output, &bound_rows, peak_bytes)
}

#[allow(clippy::too_many_arguments)]
fn enumerate_subsets(
    start: usize,
    target_size: usize,
    cur: &mut Vec<usize>,
    eligible: &[FacilityCandidate],
    demands: &[DemandPoint],
    distances: &BTreeMap<(String, String), u64>,
    objective: FacilityObjective,
    min_domains: usize,
    meter: &mut Meter<'_>,
    best_sol: &mut Option<(u64, Vec<usize>, usize, Vec<DemandAssignment>)>,
) -> Result<(), GraphError> {
    if cur.len() == target_size {
        if let Some((obj, doms, assigns)) = evaluate_subset(
            cur,
            eligible,
            demands,
            distances,
            objective,
            min_domains,
            meter,
        )? && best_sol
            .as_ref()
            .is_none_or(|b| (obj, cur.as_slice()) < (b.0, b.1.as_slice()))
        {
            *best_sol = Some((obj, cur.clone(), doms, assigns));
        }
        return Ok(());
    }
    let remaining_needed = target_size - cur.len();
    for idx in start..=eligible.len().saturating_sub(remaining_needed) {
        cur.push(idx);
        enumerate_subsets(
            idx + 1,
            target_size,
            cur,
            eligible,
            demands,
            distances,
            objective,
            min_domains,
            meter,
            best_sol,
        )?;
        cur.pop();
    }
    Ok(())
}

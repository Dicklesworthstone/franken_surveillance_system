#![forbid(unsafe_code)]
//! `ALG-SUBMOD-001`: budgeted positive-weight coverage with explicit residual gaps.
//!
//! Unlike full set cover, an unsupported target does not prevent selection for other targets.
//! Each target contributes its declared integer utility once, however many selected providers
//! support it. This is not a probability, independence assumption, value-of-information model,
//! live-coverage claim, or permission to execute the selected actions.
//!
//! The reference policy is eager marginal utility / positive integer cost, then stable action
//! identity. Ratios are compared exactly with u128 products, never floating point. Mandatory
//! actions consume both cost and slots even when they add no utility; exclusions never relax.
//! Greedy is explicitly approximate. No optimality or numerical approximation bound is claimed.

use std::collections::BTreeMap;

use fss_core::{
    CanonicalEncoder, ContentDigest, ContractError, GraphAlgorithmWitness,
    GraphAlgorithmWitnessParams, LedgerAnchor,
};

use crate::GraphError;
use crate::set_cover::{
    CoverBudget, CoverError, CoveredElement, MAX_OUTPUT_ENTRIES, MAX_WORK_UNITS, SetCoverProblem,
};

/// Existing registered submodular family; this implementation covers weighted coverage only.
pub const ALGORITHM_ID: &str = "ALG-SUBMOD-001";
/// Immutable eager reference implementation generation.
pub const IMPLEMENTATION_ID: &str =
    "fss-graph-algorithms:alg-submod-001:eager-weighted-coverage:v1";
/// Exact ratio comparison and deterministic tie/constraint policy.
pub const POLICY_ID: &str =
    "submod-policy:positive-integer-utility-and-cost:ratio-then-stable-id:mandatory-excluded:v1";
/// Complete validated input domain, distinct from minimum full-cover selection.
pub const INPUT_DOMAIN: &str = "fss.graph.budgeted_coverage_input.v1";
/// Complete result domain, including choice order, utility, costs, support and omissions.
pub const OUTPUT_DOMAIN: &str = "fss.graph.budgeted_coverage_output.v1";
/// Reproducible decision summary; it is not a stored per-evaluation transcript.
pub const DECISION_DOMAIN: &str = "fss.graph.budgeted_coverage_decision_summary.v1";

/// Immutable weighted coverage problem over the existing validated support/constraint owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmodularProblem {
    support: SetCoverProblem,
    utilities: Vec<u64>,
    costs: Vec<u64>,
    masks: Vec<u64>,
    cost_budget: u64,
    total_utility: u64,
    incidences: u64,
    digest: ContentDigest,
}

impl SubmodularProblem {
    /// All targets and all actions, including excluded actions, require exactly one positive
    /// integer value. Unknown or missing keys, zero values and total-utility overflow are errors.
    /// Mandatory actions must fit the cost budget; the support owner already enforces slots.
    /// Construction is structurally bounded by SetCoverProblem's 64-target/1024-action limits.
    pub fn new(
        support: SetCoverProblem,
        utilities: &BTreeMap<String, u64>,
        costs: &BTreeMap<String, u64>,
        cost_budget: u64,
    ) -> Result<Self, CoverError> {
        if utilities.len() != support.elements().len() || costs.len() != support.sets().len() {
            return Err(CoverError::InvalidConstraints(
                "utilities and costs must exactly cover the input identities",
            ));
        }
        let utilities = support
            .elements()
            .iter()
            .map(|id| positive(utilities, id))
            .collect::<Result<Vec<_>, _>>()?;
        let costs = support
            .sets()
            .iter()
            .map(|set| positive(costs, set.id()))
            .collect::<Result<Vec<_>, _>>()?;
        let total_utility = utilities
            .iter()
            .try_fold(0_u64, |sum, value| sum.checked_add(*value))
            .ok_or(CoverError::InvalidConstraints(
                "total declared utility exceeds u64",
            ))?;
        let mut remaining = cost_budget;
        let mut masks = Vec::with_capacity(support.sets().len());
        let mut incidences = 0;
        for (index, set) in support.sets().iter().enumerate() {
            if support.mandatory().contains(set.id()) {
                remaining =
                    remaining
                        .checked_sub(costs[index])
                        .ok_or(CoverError::InvalidConstraints(
                            "mandatory actions exceed the cost budget",
                        ))?;
            }
            let mut mask = 0_u64;
            for element in set.elements() {
                let bit = support
                    .elements()
                    .binary_search(element)
                    .map_err(|_| GraphError::UnknownNode(element.clone()))?;
                mask |= 1_u64 << bit;
                incidences += 1;
            }
            masks.push(mask);
        }
        let mut encoder = CanonicalEncoder::new();
        encoder.text(INPUT_DOMAIN);
        encoder.digest(support.digest());
        encoder.u64(cost_budget);
        encoder.u64(utilities.len() as u64);
        for utility in &utilities {
            encoder.u64(*utility);
        }
        encoder.u64(costs.len() as u64);
        for cost in &costs {
            encoder.u64(*cost);
        }
        let digest = ContentDigest::sha256(&encoder.finish());
        Ok(Self {
            support,
            utilities,
            costs,
            masks,
            cost_budget,
            total_utility,
            incidences,
            digest,
        })
    }

    /// Existing canonical support, exclusions, mandatory floor and cardinality limit.
    #[must_use]
    pub const fn support(&self) -> &SetCoverProblem {
        &self.support
    }
    /// Complete weighted objective and hard-budget identity.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Hard total cost, including mandatory actions.
    #[must_use]
    pub const fn cost_budget(&self) -> u64 {
        self.cost_budget
    }
    /// Utility of all requested targets, including targets with no eligible support.
    #[must_use]
    pub const fn total_utility(&self) -> u64 {
        self.total_utility
    }
    /// Utility values in canonical support.elements() order.
    #[must_use]
    pub fn utilities(&self) -> &[u64] {
        &self.utilities
    }
    /// Cost values in canonical support.sets() order, including excluded actions.
    #[must_use]
    pub fn costs(&self) -> &[u64] {
        &self.costs
    }

    /// Run the eager reference without an external cancellation source.
    pub fn solve(&self, budget: CoverBudget) -> Result<SubmodularAnalysis, CoverError> {
        self.solve_cancellable(budget, &|| false)
    }

    /// Solve cooperatively with explicit work and output limits. No partial result or witness is
    /// returned on cancellation, exhaustion or bound violation. No I/O, clock or thread is used.
    pub fn solve_cancellable(
        &self,
        budget: CoverBudget,
        cancelled: &impl Fn() -> bool,
    ) -> Result<SubmodularAnalysis, CoverError> {
        let mut meter = Meter {
            counters: SubmodularCounters::default(),
            limit: budget.max_work_units.min(MAX_WORK_UNITS),
            cancelled,
        };
        let n = self.support.sets().len();
        let e = self.utilities.len();
        meter.charge(
            Work::Input,
            (2 * e + 2 * n + self.support.mandatory().len() + self.support.excluded().len()) as u64
                + self.incidences,
        )?;
        let all = if e == 64 { u64::MAX } else { (1_u64 << e) - 1 };
        let mut chosen = vec![false; n];
        let mut covered = 0_u64;
        let mut available = 0_u64;
        let mut spent = 0_u64;
        let mut count = 0_usize;
        for (index, set) in self.support.sets().iter().enumerate() {
            meter.charge(Work::Check, 1)?;
            if self.support.excluded().contains(set.id()) {
                continue;
            }
            available |= self.masks[index];
            if self.support.mandatory().contains(set.id()) {
                chosen[index] = true;
                covered |= self.masks[index];
                spent += self.costs[index]; // Mandatory total was checked by construction.
                count += 1;
            }
        }
        let mut utility = self.utility(covered, &mut meter)?;
        let mut steps = Vec::new();
        let stop = loop {
            meter.check()?;
            if covered == all {
                break SelectionStop::FullCoverage;
            }
            if count == self.support.maximum_sets() {
                break SelectionStop::CardinalityLimit;
            }
            let mut best = None;
            let mut best_gain = 0_u64;
            let mut best_cost = 1_u64;
            for (index, set) in self.support.sets().iter().enumerate() {
                meter.charge(Work::Candidate, 1)?;
                if chosen[index]
                    || self.support.excluded().contains(set.id())
                    || self.costs[index] > self.cost_budget - spent
                {
                    continue;
                }
                let gain = self.utility(self.masks[index] & !covered, &mut meter)?;
                // Both products fit u128 even when the supplied integers approach u64::MAX.
                // Strict comparison keeps the first canonical identity on an exact ratio tie.
                if u128::from(gain) * u128::from(best_cost)
                    > u128::from(best_gain) * u128::from(self.costs[index])
                {
                    best = Some(index);
                    best_gain = gain;
                    best_cost = self.costs[index];
                }
            }
            let Some(index) = best else {
                break SelectionStop::NoAffordablePositiveGain;
            };
            meter.charge(Work::Check, 1)?;
            chosen[index] = true;
            covered |= self.masks[index];
            spent += best_cost;
            utility += best_gain; // Disjoint new targets; the total utility was checked.
            count += 1;
            steps.push(SelectionStep {
                action_id: self.support.sets()[index].id().to_owned(),
                marginal_utility: best_gain,
                cost_units: best_cost,
                cumulative_cost_units: spent,
                cumulative_utility: utility,
            });
        };
        if utility != self.utility(covered, &mut meter)? || spent > self.cost_budget {
            return Err(
                GraphError::Inconsistent("budgeted coverage accounting differs".into()).into(),
            );
        }
        let missing = all & !covered;
        let unsupported = all & !available;
        let output_entries = count as u64
            + steps.len() as u64
            + u64::from(missing.count_ones())
            + u64::from(unsupported.count_ones())
            + 2 * u64::from(covered.count_ones());
        let output_limit = budget.max_output_entries.min(MAX_OUTPUT_ENTRIES);
        if output_entries > output_limit {
            return Err(GraphError::BudgetExhausted {
                dimension: "output_entries",
                limit: output_limit,
            }
            .into());
        }
        let selected = self
            .support
            .sets()
            .iter()
            .enumerate()
            .filter(|(i, _)| chosen[*i])
            .map(|(_, set)| set.id().to_owned())
            .collect::<Vec<_>>();
        let mut uncovered = Vec::new();
        let mut uncoverable = Vec::new();
        let mut certificate = Vec::new();
        for (bit, element) in self.support.elements().iter().enumerate() {
            meter.charge(Work::Check, 1)?;
            let flag = 1_u64 << bit;
            if missing & flag != 0 {
                uncovered.push(element.clone());
            }
            if unsupported & flag != 0 {
                uncoverable.push(element.clone());
            }
            if covered & flag != 0 {
                for (index, set) in self.support.sets().iter().enumerate() {
                    meter.charge(Work::Check, 1)?;
                    if chosen[index] && self.masks[index] & flag != 0 {
                        certificate.push(CoveredElement {
                            element: element.clone(),
                            set_id: set.id().to_owned(),
                        });
                        break;
                    }
                }
            }
        }
        meter.counters.check_bound(n as u64, e as u64)?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text(OUTPUT_DOMAIN);
        encoder.digest(self.digest);
        encoder.text(stop.as_str());
        encoder.u64(spent);
        encoder.u64(utility);
        encoder.u64(self.total_utility);
        for ids in [&selected, &uncovered, &uncoverable] {
            encoder.u64(ids.len() as u64);
            for id in ids {
                encoder.text(id);
            }
        }
        encoder.u64(certificate.len() as u64);
        for row in &certificate {
            encoder.text(&row.element);
            encoder.text(&row.set_id);
        }
        encoder.u64(steps.len() as u64);
        for step in &steps {
            encoder.text(&step.action_id);
            encoder.u64(step.marginal_utility);
            encoder.u64(step.cost_units);
            encoder.u64(step.cumulative_cost_units);
            encoder.u64(step.cumulative_utility);
        }
        let output_digest = ContentDigest::sha256(&encoder.finish());
        let mut encoder = CanonicalEncoder::new();
        encoder.text(DECISION_DOMAIN);
        encoder.digest(self.digest);
        encoder.text(IMPLEMENTATION_ID);
        encoder.text(POLICY_ID);
        for (key, value) in meter.counters.to_map() {
            encoder.text(&key);
            encoder.u64(value);
        }
        encoder.digest(output_digest);
        let decision_digest = ContentDigest::sha256(&encoder.finish());
        meter.check()?;
        Ok(SubmodularAnalysis {
            stop,
            selected,
            uncovered,
            uncoverable,
            certificate,
            steps,
            cost_units: spent,
            utility,
            total_utility: self.total_utility,
            input_digest: self.digest,
            output_digest,
            decision_digest,
            counters: meter.counters,
            output_entries,
            node_count: (n + e) as u64,
            edge_count: self.incidences,
            workspace_bytes: 8192
                + (3 * n + 8 * e) as u64 * (4 * crate::graph::MAX_NODE_ID_LEN as u64 + 1024),
        })
    }

    fn utility<F: Fn() -> bool>(
        &self,
        mut mask: u64,
        meter: &mut Meter<'_, F>,
    ) -> Result<u64, CoverError> {
        let mut value = 0;
        while mask != 0 {
            meter.charge(Work::Term, 1)?;
            value += self.utilities[mask.trailing_zeros() as usize];
            mask &= mask - 1;
        }
        Ok(value)
    }
}

fn positive(values: &BTreeMap<String, u64>, id: &str) -> Result<u64, CoverError> {
    values
        .get(id)
        .copied()
        .filter(|value| *value > 0)
        .ok_or(CoverError::InvalidConstraints(
            "every known identity needs a positive integer value",
        ))
}

/// Why this completed selection stopped; none of these prove greedy optimality or infeasibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionStop {
    /// Every requested target has selected support, not a proof about the physical world.
    FullCoverage,
    /// The hard action-count ceiling is reached, possibly with residual gaps.
    CardinalityLimit,
    /// No remaining eligible action both fits the remaining cost and adds positive utility.
    NoAffordablePositiveGain,
}
impl SelectionStop {
    /// Stable report spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FullCoverage => "full_coverage",
            Self::CardinalityLimit => "cardinality_limit",
            Self::NoAffordablePositiveGain => "no_affordable_positive_gain",
        }
    }
}

/// One optional action in deterministic choice order; mandatory actions precede these totals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionStep {
    /// Exact selected action identity.
    pub action_id: String,
    /// Utility of newly supported targets only, without double counting shared targets.
    pub marginal_utility: u64,
    /// Positive declared integer cost of this action.
    pub cost_units: u64,
    /// Total selected cost, including all mandatory actions.
    pub cumulative_cost_units: u64,
    /// Total distinct supported target utility, including mandatory support.
    pub cumulative_utility: u64,
}

/// Charged logical work; construction and allocation have separate structural bounds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SubmodularCounters {
    /// Values, identities, incidence and constraint entries read.
    pub input_entries: u64,
    /// Actions scanned across greedy rounds, including ineligible actions.
    pub candidate_scans: u64,
    /// Target utility terms actually summed for marginal and result evaluations.
    pub utility_terms: u64,
    /// Mandatory admissions, selected updates and support checks.
    pub result_checks: u64,
}
impl SubmodularCounters {
    /// Total charged to the hard-clamped physical work allowance.
    #[must_use]
    pub const fn work_units(self) -> u64 {
        self.input_entries + self.candidate_scans + self.utility_terms + self.result_checks
    }
    /// Canonical counters carried by the graph witness.
    #[must_use]
    pub fn to_map(self) -> BTreeMap<String, u64> {
        BTreeMap::from([
            ("input_entries".into(), self.input_entries),
            ("candidate_scans".into(), self.candidate_scans),
            ("utility_terms".into(), self.utility_terms),
            ("result_checks".into(), self.result_checks),
        ])
    }
    fn check_bound(self, n: u64, e: u64) -> Result<(), CoverError> {
        // Each successful round covers a new positive-utility target; at most one final failed
        // round is possible. The certificate scans each action at most once per target.
        for (counter, observed, bound) in [
            ("input_entries", self.input_entries, 2 * e + 4 * n + n * e),
            ("candidate_scans", self.candidate_scans, n * (e + 1)),
            ("utility_terms", self.utility_terms, e * (n * (e + 1) + 2)),
            ("result_checks", self.result_checks, n + 2 * e + n * e),
        ] {
            if observed > bound {
                return Err(GraphError::ComplexityBoundViolated {
                    counter,
                    observed,
                    bound,
                }
                .into());
            }
        }
        Ok(())
    }
}

/// Complete immutable algorithm result, independent of unused physical execution allowance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmodularAnalysis {
    stop: SelectionStop,
    selected: Vec<String>,
    uncovered: Vec<String>,
    uncoverable: Vec<String>,
    certificate: Vec<CoveredElement>,
    steps: Vec<SelectionStep>,
    cost_units: u64,
    utility: u64,
    total_utility: u64,
    input_digest: ContentDigest,
    output_digest: ContentDigest,
    decision_digest: ContentDigest,
    counters: SubmodularCounters,
    output_entries: u64,
    node_count: u64,
    edge_count: u64,
    workspace_bytes: u64,
}
impl SubmodularAnalysis {
    /// Deterministic policy stop, separate from graph algorithm completion.
    #[must_use]
    pub const fn stop(&self) -> SelectionStop {
        self.stop
    }
    /// Canonical selected identities, including mandatory zero-support actions.
    #[must_use]
    pub fn selected(&self) -> &[String] {
        &self.selected
    }
    /// Every requested target missing from this selection, including structurally unsupported ones.
    #[must_use]
    pub fn uncovered(&self) -> &[String] {
        &self.uncovered
    }
    /// Targets with no eligible supporting action even without cost or cardinality ceilings.
    #[must_use]
    pub fn uncoverable(&self) -> &[String] {
        &self.uncoverable
    }
    /// First canonical selected provider for each supported target.
    #[must_use]
    pub fn certificate(&self) -> &[CoveredElement] {
        &self.certificate
    }
    /// Optional choices with exact integer marginal gains and cumulative accounting.
    #[must_use]
    pub fn steps(&self) -> &[SelectionStep] {
        &self.steps
    }
    /// Total declared cost consumed, including mandatory actions.
    #[must_use]
    pub const fn cost_units(&self) -> u64 {
        self.cost_units
    }
    /// Total utility of distinct selected-supported targets.
    #[must_use]
    pub const fn utility(&self) -> u64 {
        self.utility
    }
    /// Total requested utility, including unsupported targets.
    #[must_use]
    pub const fn total_utility(&self) -> u64 {
        self.total_utility
    }
    /// Complete support, weight, cost and hard-budget input identity.
    #[must_use]
    pub const fn input_digest(&self) -> ContentDigest {
        self.input_digest
    }
    /// Complete selected result, choice sequence and residual-gap identity.
    #[must_use]
    pub const fn output_digest(&self) -> ContentDigest {
        self.output_digest
    }
    /// Actual bounded logical work counters.
    #[must_use]
    pub const fn counters(&self) -> SubmodularCounters {
        self.counters
    }
    /// Approximate reference witness. Its parent must pin authorized source and interpretation.
    /// The workspace value is a conservative solver bound, not a measured allocator peak.
    pub fn witness(
        &self,
        projection_id: &str,
        anchor: LedgerAnchor,
    ) -> Result<GraphAlgorithmWitness, ContractError> {
        GraphAlgorithmWitness::new(GraphAlgorithmWitnessParams {
            algorithm_id: ALGORITHM_ID.to_owned(),
            implementation_id: IMPLEMENTATION_ID.to_owned(),
            projection_id: projection_id.to_owned(),
            anchor,
            node_count: self.node_count,
            edge_count: self.edge_count,
            input_digest: self.input_digest,
            policy_id: POLICY_ID.to_owned(),
            dominant_operation_counts: self.counters.to_map(),
            peak_working_bytes: self.workspace_bytes,
            budget_consumed: BTreeMap::from([
                ("work_units".into(), self.counters.work_units()),
                ("output_entries".into(), self.output_entries),
            ]),
            exactness: "approximate".to_owned(),
            error_bound: None,
            stop_reason: GraphAlgorithmWitness::STOP_COMPLETED.to_owned(),
            decision_path_digest: self.decision_digest,
            output_digest: self.output_digest,
        })
    }
}

enum Work {
    Input,
    Candidate,
    Term,
    Check,
}
struct Meter<'a, F: Fn() -> bool> {
    counters: SubmodularCounters,
    limit: u64,
    cancelled: &'a F,
}
impl<F: Fn() -> bool> Meter<'_, F> {
    fn check(&self) -> Result<(), CoverError> {
        if (self.cancelled)() {
            Err(CoverError::Cancelled)
        } else {
            Ok(())
        }
    }
    fn charge(&mut self, work: Work, amount: u64) -> Result<(), CoverError> {
        self.check()?;
        if amount > self.limit.saturating_sub(self.counters.work_units()) {
            return Err(GraphError::BudgetExhausted {
                dimension: "work_units",
                limit: self.limit,
            }
            .into());
        }
        match work {
            Work::Input => self.counters.input_entries += amount,
            Work::Candidate => self.counters.candidate_scans += amount,
            Work::Term => self.counters.utility_terms += amount,
            Work::Check => self.counters.result_checks += amount,
        }
        Ok(())
    }
}

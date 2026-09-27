#![forbid(unsafe_code)]
//! `ALG-SETCOVER-001`: bounded unit-cost evidence/sensor set selection.
//!
//! Exact-small searches subsets in cardinality then stable set-identity order. Greedy selects
//! maximum remaining marginal gain, then stable identity, and NEVER labels a failed greedy
//! search infeasible. Mandatory sets and exclusions are hard constraints. Every requested
//! element remains explicit, including elements with no eligible observer. Cost here is the
//! number of selected sets, NOT money, information value, detection quality, or effect risk.
//!
//! Inputs are immutable, canonical and bounded. Work and output ceilings and an explicit
//! cancellation probe apply to both methods. Exhaustion/cancellation returns no answer and no
//! witness. Successful analysis carries the existing GraphAlgorithmWitness contract; the
//! exact/heuristic distinction and incomplete-coverage status are independent fields.
//!
//! This is a reference implementation candidate for FSS-160, not INT-FNX-001 qualification.
//! Source authorization, common-window selection, privacy and current-world validity belong
//! to the caller. Selecting evidence does not authorize stopping a camera or executing a plan.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{
    CanonicalEncoder, ContentDigest, ContractError, GraphAlgorithmWitness,
    GraphAlgorithmWitnessParams, LedgerAnchor,
};

use crate::{CoverageObservation, GraphError, SensorCoverageProjection};

/// Registered algorithm identity.
pub const ALGORITHM_ID: &str = "ALG-SETCOVER-001";
/// At most one machine-word universe; the sixty-fourth bit is supported.
pub const MAX_ELEMENTS: usize = 64;
/// Maximum covering sets, including excluded and mandatory sets.
pub const MAX_SETS: usize = 1024;
/// Maximum optional eligible sets admitted to exhaustive search; no heuristic fallback.
pub const MAX_EXACT_OPTIONAL_SETS: usize = 20;
/// Maximum facts admitted by the retained-coverage adapter before rebuilding its graph.
pub const MAX_COVERAGE_FACTS: usize = 8192;
/// Independent hard work ceiling (a larger caller budget never raises it).
pub const MAX_WORK_UNITS: u64 = 50_000_000;
/// Independent hard ceiling on output identities.
pub const MAX_OUTPUT_ENTRIES: u64 = 8192;
/// Canonical input domain. This binds objective, sets, mandatory/excluded identities and limit.
pub const INPUT_DOMAIN: &str = "fss.graph.set_cover_input.v1";
/// Canonical result domain; method, coverage disposition and certificate are separate fields.
pub const OUTPUT_DOMAIN: &str = "fss.graph.set_cover_output.v1";
/// Decision-summary domain. It is a reproducible summary, not a stored per-branch transcript.
pub const DECISION_DOMAIN: &str = "fss.graph.set_cover_decision_summary.v1";

/// Selection algorithm; changing the method changes its implementation/policy identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverMethod {
    /// Exhaustive minimum cardinality, then lexicographically smallest stable set tuple.
    ExactSmall,
    /// Maximum remaining gain, then stable set identity; not necessarily minimum cardinality.
    Greedy,
}
impl CoverMethod {
    /// Stable spelling used in reports and canonical bytes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExactSmall => "exact_small",
            Self::Greedy => "greedy",
        }
    }
    /// Method-specific immutable implementation generation.
    #[must_use]
    pub const fn implementation_id(self) -> &'static str {
        match self {
            Self::ExactSmall => "fss-graph-algorithms:alg-setcover-001:cardinality-enumeration:v1",
            Self::Greedy => "fss-graph-algorithms:alg-setcover-001:marginal-gain:v1",
        }
    }
    /// Exactness of the search, not an assertion about physical observability.
    #[must_use]
    pub const fn exactness(self) -> &'static str {
        match self {
            Self::ExactSmall => "exact",
            Self::Greedy => "approximate",
        }
    }
    /// Unit-cost, hard-constraint and tie-break semantics.
    #[must_use]
    pub const fn policy_id(self) -> &'static str {
        match self {
            Self::ExactSmall => "setcover-policy:unit-cost:mandatory-excluded:cardinality-then-stable-set-tuple:v1",
            Self::Greedy => "setcover-policy:unit-cost:mandatory-excluded:marginal-gain-then-stable-set-id:v1",
        }
    }
}

/// A canonical covering set. Empty support is allowed and never invented into coverage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverSet {
    id: String,
    elements: BTreeSet<String>,
}
impl CoverSet {
    /// Construct a bounded set; duplicate elements and invalid identities are errors.
    pub fn new(id: &str, elements: &[String]) -> Result<Self, CoverError> {
        valid_id(id)?;
        if elements.len() > MAX_ELEMENTS {
            return Err(GraphError::TooLarge.into());
        }
        Ok(Self {
            id: id.to_owned(),
            elements: unique_ids(elements)?,
        })
    }
    /// Stable set identity.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Canonical support.
    #[must_use]
    pub fn elements(&self) -> &BTreeSet<String> {
        &self.elements
    }
}

/// Explicit work/output allowance, independent of the selected-set cardinality constraint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverBudget {
    /// Input entries, candidate evaluations, mask updates, branch nodes and result checks.
    pub max_work_units: u64,
    /// Selected, uncovered, uncoverable and certificate identities emitted.
    pub max_output_entries: u64,
}
impl Default for CoverBudget {
    fn default() -> Self {
        Self { max_work_units: 2_000_000, max_output_entries: MAX_OUTPUT_ENTRIES }
    }
}

/// No graph result exists on any error, including cancellation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoverError {
    /// Existing typed input, budget, or complexity failure.
    Graph(GraphError),
    /// Mutually inconsistent hard constraints, not a failed search.
    InvalidConstraints(&'static str),
    /// Cooperative cancellation. It is not infeasibility or budget exhaustion.
    Cancelled,
}
impl From<GraphError> for CoverError {
    fn from(error: GraphError) -> Self { Self::Graph(error) }
}
impl fmt::Display for CoverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Graph(error) => write!(f, "{error}"),
            Self::InvalidConstraints(reason) => write!(f, "invalid set-cover constraints: {reason}"),
            Self::Cancelled => f.write_str("set-cover selection cancelled; no answer or witness"),
        }
    }
}
impl std::error::Error for CoverError {}

fn valid_id(id: &str) -> Result<(), CoverError> {
    if id.is_empty() || id.len() > crate::graph::MAX_NODE_ID_LEN || id.chars().any(char::is_control) {
        Err(GraphError::InvalidNodeId(id.to_owned()).into())
    } else {
        Ok(())
    }
}
fn unique_ids(values: &[String]) -> Result<BTreeSet<String>, CoverError> {
    let mut result = BTreeSet::new();
    for value in values {
        valid_id(value)?;
        if !result.insert(value.clone()) {
            return Err(GraphError::DuplicateNode(value.clone()).into());
        }
    }
    Ok(result)
}
fn encode_ids<'a>(encoder: &mut CanonicalEncoder, values: impl ExactSizeIterator<Item = &'a String>) {
    encoder.u64(values.len() as u64);
    for value in values { encoder.text(value); }
}

/// Immutable set-cover problem. No public field can replace masks or identity after validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetCoverProblem {
    elements: Vec<String>,
    sets: Vec<CoverSet>,
    masks: Vec<u64>,
    mandatory: BTreeSet<String>,
    excluded: BTreeSet<String>,
    maximum_sets: usize,
    incidences: u64,
    input_digest: ContentDigest,
}
impl SetCoverProblem {
    /// Build an explicit objective. Every support must name a requested element. Exclusions and
    /// mandatory sets must name existing sets and cannot overlap. A mandatory floor larger than
    /// `maximum_sets` is a contract error; no constraint is relaxed to make a solution possible.
    pub fn new(
        elements: &[String], sets: &[CoverSet], mandatory: &[String], excluded: &[String],
        maximum_sets: usize,
    ) -> Result<Self, CoverError> {
        if elements.len() > MAX_ELEMENTS || sets.len() > MAX_SETS || mandatory.len() > MAX_SETS
            || excluded.len() > MAX_SETS || maximum_sets > MAX_SETS {
            return Err(GraphError::TooLarge.into());
        }
        let elements: Vec<String> = unique_ids(elements)?.into_iter().collect();
        let mandatory = unique_ids(mandatory)?;
        let excluded = unique_ids(excluded)?;
        if mandatory.len() > maximum_sets {
            return Err(CoverError::InvalidConstraints("mandatory sets exceed the selection limit"));
        }
        if !mandatory.is_disjoint(&excluded) {
            return Err(CoverError::InvalidConstraints("a mandatory set is excluded"));
        }
        let mut ordered = BTreeMap::new();
        for set in sets {
            if ordered.insert(set.id.clone(), set.clone()).is_some() {
                return Err(GraphError::DuplicateNode(set.id.clone()).into());
            }
        }
        for id in mandatory.iter().chain(excluded.iter()) {
            if !ordered.contains_key(id) { return Err(GraphError::UnknownNode(id.clone()).into()); }
        }
        let sets: Vec<CoverSet> = ordered.into_values().collect();
        let mut masks = Vec::with_capacity(sets.len());
        let mut incidences = 0;
        for set in &sets {
            let mut mask = 0_u64;
            for element in &set.elements {
                let bit = elements.binary_search(element)
                    .map_err(|_| GraphError::UnknownNode(element.clone()))?;
                mask |= 1_u64 << bit;
                incidences += 1;
            }
            masks.push(mask);
        }
        let mut encoder = CanonicalEncoder::new();
        encoder.text(INPUT_DOMAIN);
        encode_ids(&mut encoder, elements.iter());
        encoder.u64(sets.len() as u64);
        for set in &sets {
            encoder.text(&set.id);
            encode_ids(&mut encoder, set.elements.iter());
        }
        encode_ids(&mut encoder, mandatory.iter());
        encode_ids(&mut encoder, excluded.iter());
        encoder.u64(maximum_sets as u64);
        let input_digest = ContentDigest::sha256(&encoder.finish());
        Ok(Self { elements, sets, masks, mandatory, excluded, maximum_sets, incidences, input_digest })
    }

    /// Build from an already authorized, window-selected coverage projection. Unknown requested
    /// zones remain in the objective with zero support. Every known sensor remains a candidate,
    /// including sensors with no qualifying witness. No time, geometry, or independence is inferred.
    /// Public projection fields are cross-checked against a canonical rebuild before use.
    pub fn from_coverage(
        projection: &SensorCoverageProjection, elements: &[String], mandatory: &[String],
        excluded: &[String], maximum_sets: usize,
    ) -> Result<Self, CoverError> {
        if projection.witnesses.len() > MAX_COVERAGE_FACTS || elements.len() > MAX_ELEMENTS
            || mandatory.len() > MAX_SETS || excluded.len() > MAX_SETS || maximum_sets > MAX_SETS {
            return Err(GraphError::TooLarge.into());
        }
        let requested = unique_ids(elements)?;
        let site = projection.plane.strip_prefix(crate::coverage::PLANE_PREFIX)
            .ok_or(CoverError::InvalidConstraints("invalid evidence-plane root"))?;
        let mut facts = Vec::with_capacity(projection.witnesses.len());
        let mut supports: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for ((sensor, zone), count) in &projection.witnesses {
            let entry = supports.entry(sensor.clone()).or_default();
            if *count > 0 && requested.contains(zone) { entry.push(zone.clone()); }
            facts.push(CoverageObservation {
                sensor_id: sensor.clone(), zone_scope: zone.clone(), witnesses: *count,
            });
        }
        if supports.len() > MAX_SETS { return Err(GraphError::TooLarge.into()); }
        if SensorCoverageProjection::build(site, &facts)? != *projection {
            return Err(GraphError::Inconsistent("coverage graph and witness facts differ".into()).into());
        }
        let sets = supports.into_iter().map(|(id, support)| CoverSet::new(&id, &support))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(elements, &sets, mandatory, excluded, maximum_sets)
    }
    /// Exact input identity, independent of physical execution budgets.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest { self.input_digest }
    /// Canonical objective. Uncoverable elements are never removed.
    #[must_use]
    pub fn elements(&self) -> &[String] { &self.elements }
    /// Canonical candidate inventory.
    #[must_use]
    pub fn sets(&self) -> &[CoverSet] { &self.sets }
    /// Mandatory floor.
    #[must_use]
    pub fn mandatory(&self) -> &BTreeSet<String> { &self.mandatory }
    /// Explicit exclusions.
    #[must_use]
    pub fn excluded(&self) -> &BTreeSet<String> { &self.excluded }
    /// Maximum number of selected sets, including mandatory ones.
    #[must_use]
    pub const fn maximum_sets(&self) -> usize { self.maximum_sets }

    /// Solve without a cancellation source. Uses the same bounded implementation.
    pub fn solve(&self, method: CoverMethod, budget: CoverBudget) -> Result<CoverAnalysis, CoverError> {
        self.solve_cancellable(method, budget, &|| false)
    }
    /// Solve with a request-owned cooperative cancellation probe. It is polled for every charged
    /// work item and immediately before returning an answer. No thread, clock or I/O is acquired.
    pub fn solve_cancellable(
        &self, method: CoverMethod, budget: CoverBudget, cancelled: &impl Fn() -> bool,
    ) -> Result<CoverAnalysis, CoverError> {
        let mut meter = Meter::new(budget, cancelled);
        meter.charge(Work::Input, (self.elements.len() + self.sets.len() + self.mandatory.len()
            + self.excluded.len()) as u64 + self.incidences)?;
        let all = if self.elements.len() == 64 { u64::MAX } else { (1_u64 << self.elements.len()) - 1 };
        let mut selected = Vec::new();
        let mut optional = Vec::new();
        let mut covered = 0;
        let mut available = 0;
        for (index, set) in self.sets.iter().enumerate() {
            meter.charge(Work::Update, 1)?;
            if self.excluded.contains(&set.id) { continue; }
            available |= self.masks[index];
            if self.mandatory.contains(&set.id) {
                selected.push(index);
                covered |= self.masks[index];
            } else { optional.push(index); }
        }
        // Exact search never silently becomes greedy, including overlarge trivial requests.
        if method == CoverMethod::ExactSmall && optional.len() > MAX_EXACT_OPTIONAL_SETS {
            return Err(GraphError::TooLarge.into());
        }
        let missing_possible = all & !available;
        let status = if missing_possible != 0 {
            CoverStatus::Uncoverable
        } else if covered == all {
            CoverStatus::Covered
        } else {
            match method {
                CoverMethod::ExactSmall => {
                    if let Some(extra) = exact(&self.masks, &optional, covered, all,
                        self.maximum_sets - selected.len(), &mut meter)? {
                        selected.extend(extra);
                        CoverStatus::Covered
                    } else { CoverStatus::InfeasibleWithinLimit }
                }
                CoverMethod::Greedy => {
                    greedy(&self.masks, &optional, &mut selected, &mut covered, all,
                        self.maximum_sets, &mut meter)?;
                    if covered == all { CoverStatus::Covered } else { CoverStatus::HeuristicIncomplete }
                }
            }
        };
        // Preserve choice order in the decision summary, but expose a canonical selected set.
        let choice_order = selected.clone();
        selected.sort_unstable();
        covered = 0;
        for &index in &selected { meter.charge(Work::Check, 1)?; covered |= self.masks[index]; }
        if (status == CoverStatus::Covered) != (covered == all) {
            return Err(GraphError::Inconsistent("set-cover disposition disagrees with selected support".into()).into());
        }
        let uncovered_mask = all & !covered;
        let output_entries = selected.len() as u64 + u64::from(uncovered_mask.count_ones())
            + u64::from(missing_possible.count_ones()) + 2 * u64::from(covered.count_ones());
        if output_entries > budget.max_output_entries.min(MAX_OUTPUT_ENTRIES) {
            return Err(GraphError::BudgetExhausted {
                dimension: "output_entries", limit: budget.max_output_entries.min(MAX_OUTPUT_ENTRIES),
            }.into());
        }
        let mut certificate = Vec::new();
        let mut uncovered = Vec::new();
        let mut uncoverable = Vec::new();
        for (bit, element) in self.elements.iter().enumerate() {
            let flag = 1_u64 << bit;
            meter.charge(Work::Check, 1)?;
            if uncovered_mask & flag != 0 { uncovered.push(element.clone()); }
            if missing_possible & flag != 0 { uncoverable.push(element.clone()); }
            if covered & flag != 0 {
                for &index in &selected {
                    meter.charge(Work::Check, 1)?;
                    if self.masks[index] & flag != 0 {
                        certificate.push(CoveredElement { element: element.clone(), set_id: self.sets[index].id.clone() });
                        break;
                    }
                }
            }
        }
        check_bound(self.sets.len(), self.elements.len(), optional.len(), method, &meter.counters)?;
        let selected: Vec<String> = selected.iter().map(|&index| self.sets[index].id.clone()).collect();
        let mut encoder = CanonicalEncoder::new();
        encoder.text(OUTPUT_DOMAIN);
        encoder.digest(self.input_digest);
        encoder.text(method.as_str());
        encoder.text(status.as_str());
        encode_ids(&mut encoder, selected.iter());
        encode_ids(&mut encoder, uncovered.iter());
        encode_ids(&mut encoder, uncoverable.iter());
        encoder.u64(certificate.len() as u64);
        for row in &certificate { encoder.text(&row.element); encoder.text(&row.set_id); }
        let output_digest = ContentDigest::sha256(&encoder.finish());
        let mut encoder = CanonicalEncoder::new();
        encoder.text(DECISION_DOMAIN);
        encoder.digest(self.input_digest);
        encoder.text(method.implementation_id());
        encoder.text(method.policy_id());
        encoder.u64(choice_order.len() as u64);
        for index in choice_order { encoder.text(&self.sets[index].id); }
        for (key, value) in meter.counters.to_map() { encoder.text(&key); encoder.u64(value); }
        encoder.digest(output_digest);
        let decision_path_digest = ContentDigest::sha256(&encoder.finish());
        meter.check()?;
        Ok(CoverAnalysis {
            method, status, selected, uncovered, uncoverable, certificate,
            input_digest: self.input_digest, output_digest, decision_path_digest,
            node_count: (self.elements.len() + self.sets.len()) as u64,
            edge_count: self.incidences, counters: meter.counters, output_entries,
            // Conservative charged workspace, not an allocator-measured high-water mark.
            // Includes bounded index vectors, certificate/string construction and canonical encoders.
            workspace_bytes: 4096 + (self.sets.len() + 4 * self.elements.len()) as u64
                * (4 * crate::graph::MAX_NODE_ID_LEN as u64 + 512),
        })
    }
}

/// An algorithm finishing is distinct from its selected sets covering the objective.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverStatus {
    /// Every requested element has a positive support certificate from a selected set.
    Covered,
    /// Some requested element has no eligible covering set, even without the cardinality limit.
    Uncoverable,
    /// Exhaustive exact-small search proved no full cover within the cardinality limit.
    InfeasibleWithinLimit,
    /// Greedy ran out of selection slots; a feasible cover may still exist.
    HeuristicIncomplete,
}
impl CoverStatus {
    /// Stable orthogonal coverage disposition.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Covered => "covered",
            Self::Uncoverable => "uncoverable",
            Self::InfeasibleWithinLimit => "infeasible_within_limit",
            Self::HeuristicIncomplete => "heuristic_incomplete",
        }
    }
}

/// One positive support edge, not a coverage or absence witness in its own right.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoveredElement {
    /// Required element identity.
    pub element: String,
    /// Lexicographically first selected set supporting it.
    pub set_id: String,
}

/// Charged logical work. Input canonicalization has hard structural bounds; these are solve costs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CoverCounters {
    /// Objective, set, membership and hard-constraint entries admitted.
    pub input_entries: u64,
    /// Greedy marginal-gain evaluations.
    pub candidate_evaluations: u64,
    /// Input-union and search mask updates.
    pub coverage_updates: u64,
    /// Exact subset leaves tested, including the empty optional subset.
    pub branch_nodes: u64,
    /// Result support and certificate checks.
    pub result_checks: u64,
}
impl CoverCounters {
    /// Exact sum charged to `max_work_units`.
    #[must_use]
    pub const fn work_units(&self) -> u64 {
        self.input_entries + self.candidate_evaluations + self.coverage_updates
            + self.branch_nodes + self.result_checks
    }
    /// Canonical witness counter map.
    #[must_use]
    pub fn to_map(self) -> BTreeMap<String, u64> {
        BTreeMap::from([
            ("input_entries".into(), self.input_entries),
            ("candidate_evaluations".into(), self.candidate_evaluations),
            ("coverage_updates".into(), self.coverage_updates),
            ("branch_nodes".into(), self.branch_nodes),
            ("result_checks".into(), self.result_checks),
        ])
    }
}

/// A complete algorithm run with private, immutable witness-bearing result fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverAnalysis {
    method: CoverMethod,
    status: CoverStatus,
    selected: Vec<String>,
    uncovered: Vec<String>,
    uncoverable: Vec<String>,
    certificate: Vec<CoveredElement>,
    input_digest: ContentDigest,
    output_digest: ContentDigest,
    decision_path_digest: ContentDigest,
    node_count: u64,
    edge_count: u64,
    counters: CoverCounters,
    output_entries: u64,
    workspace_bytes: u64,
}
impl CoverAnalysis {
    /// Executed method; never changed by pressure or a failed exact search.
    #[must_use]
    pub const fn method(&self) -> CoverMethod { self.method }
    /// Coverage status independent of search exactness.
    #[must_use]
    pub const fn status(&self) -> CoverStatus { self.status }
    /// Selected identities. An incomplete result is not an approved partial execution plan.
    #[must_use]
    pub fn selected(&self) -> &[String] { &self.selected }
    /// Every requested element not supported by the returned selection.
    #[must_use]
    pub fn uncovered(&self) -> &[String] { &self.uncovered }
    /// Elements with no eligible supporting set at all.
    #[must_use]
    pub fn uncoverable(&self) -> &[String] { &self.uncoverable }
    /// One canonical positive support edge for each element covered by the selection.
    #[must_use]
    pub fn certificate(&self) -> &[CoveredElement] { &self.certificate }
    /// Exact canonical objective/input digest.
    #[must_use]
    pub const fn input_digest(&self) -> ContentDigest { self.input_digest }
    /// Complete result digest, independent of unused physical execution budget.
    #[must_use]
    pub const fn output_digest(&self) -> ContentDigest { self.output_digest }
    /// Actual logical work charged to this run.
    #[must_use]
    pub const fn counters(&self) -> CoverCounters { self.counters }
    /// Existing graph witness, pinned by the caller to an authorized parent projection and anchor.
    /// The witness means the algorithm completed, NOT that `status()` is `Covered`.
    pub fn witness(&self, projection_id: &str, anchor: LedgerAnchor) -> Result<GraphAlgorithmWitness, ContractError> {
        GraphAlgorithmWitness::new(GraphAlgorithmWitnessParams {
            algorithm_id: ALGORITHM_ID.to_owned(),
            implementation_id: self.method.implementation_id().to_owned(),
            projection_id: projection_id.to_owned(), anchor,
            node_count: self.node_count, edge_count: self.edge_count, input_digest: self.input_digest,
            policy_id: self.method.policy_id().to_owned(), dominant_operation_counts: self.counters.to_map(),
            peak_working_bytes: self.workspace_bytes,
            budget_consumed: BTreeMap::from([
                ("work_units".to_owned(), self.counters.work_units()),
                ("output_entries".to_owned(), self.output_entries),
            ]),
            exactness: self.method.exactness().to_owned(), error_bound: None,
            stop_reason: GraphAlgorithmWitness::STOP_COMPLETED.to_owned(),
            decision_path_digest: self.decision_path_digest, output_digest: self.output_digest,
        })
    }
}

enum Work { Input, Candidate, Update, Branch, Check }
struct Meter<'a, F: Fn() -> bool> {
    counters: CoverCounters,
    limit: u64,
    cancelled: &'a F,
}
impl<'a, F: Fn() -> bool> Meter<'a, F> {
    fn new(budget: CoverBudget, cancelled: &'a F) -> Self {
        Self { counters: CoverCounters::default(), limit: budget.max_work_units.min(MAX_WORK_UNITS), cancelled }
    }
    fn check(&self) -> Result<(), CoverError> {
        if (self.cancelled)() { Err(CoverError::Cancelled) } else { Ok(()) }
    }
    fn charge(&mut self, kind: Work, amount: u64) -> Result<(), CoverError> {
        self.check()?;
        if amount > self.limit.saturating_sub(self.counters.work_units()) {
            return Err(GraphError::BudgetExhausted { dimension: "work_units", limit: self.limit }.into());
        }
        match kind {
            Work::Input => self.counters.input_entries += amount,
            Work::Candidate => self.counters.candidate_evaluations += amount,
            Work::Update => self.counters.coverage_updates += amount,
            Work::Branch => self.counters.branch_nodes += amount,
            Work::Check => self.counters.result_checks += amount,
        }
        Ok(())
    }
}

fn exact<F: Fn() -> bool>(
    masks: &[u64], optional: &[usize], mandatory_mask: u64, all: u64,
    room: usize, meter: &mut Meter<'_, F>,
) -> Result<Option<Vec<usize>>, CoverError> {
    for size in 0..=room.min(optional.len()) {
        let mut indices: Vec<usize> = (0..size).collect();
        loop {
            meter.charge(Work::Branch, 1)?;
            let mut covered = mandatory_mask;
            for &at in &indices {
                meter.charge(Work::Update, 1)?;
                covered |= masks[optional[at]];
            }
            if covered == all {
                return Ok(Some(indices.iter().map(|&at| optional[at]).collect()));
            }
            if !next_combination(&mut indices, optional.len()) { break; }
        }
    }
    Ok(None)
}

// Lexicographic fixed-cardinality enumeration. Zero length has exactly one combination.
fn next_combination(indices: &mut [usize], count: usize) -> bool {
    for at in (0..indices.len()).rev() {
        if indices[at] < count - indices.len() + at {
            indices[at] += 1;
            for later in at + 1..indices.len() { indices[later] = indices[later - 1] + 1; }
            return true;
        }
    }
    false
}

fn greedy<F: Fn() -> bool>(
    masks: &[u64], optional: &[usize], selected: &mut Vec<usize>, covered: &mut u64,
    all: u64, maximum_sets: usize, meter: &mut Meter<'_, F>,
) -> Result<(), CoverError> {
    let mut used = vec![false; masks.len()];
    while *covered != all && selected.len() < maximum_sets {
        let mut best = None;
        let mut gain = 0;
        for &index in optional {
            meter.charge(Work::Candidate, 1)?;
            if used[index] { continue; }
            let candidate_gain = (masks[index] & !*covered).count_ones();
            // Strict comparison preserves the earlier canonical identity on equal gain.
            if candidate_gain > gain { best = Some(index); gain = candidate_gain; }
        }
        let Some(index) = best else { break; };
        meter.charge(Work::Update, 1)?;
        used[index] = true;
        selected.push(index);
        *covered |= masks[index];
    }
    Ok(())
}

fn check_bound(sets: usize, elements: usize, optional: usize, method: CoverMethod, c: &CoverCounters) -> Result<(), CoverError> {
    let n = sets as u64;
    let e = elements as u64;
    let subsets = if method == CoverMethod::ExactSmall { 1_u64 << optional } else { 0 };
    let rows = [
        ("input_entries", c.input_entries, e + 3 * n + n * e),
        ("branch_nodes", c.branch_nodes, subsets),
        ("candidate_evaluations", c.candidate_evaluations, if method == CoverMethod::Greedy { n * e } else { 0 }),
        ("coverage_updates", c.coverage_updates, n + subsets * optional as u64 + e),
        ("result_checks", c.result_checks, n + e * (n + 1)),
    ];
    for (counter, observed, bound) in rows {
        if observed > bound { return Err(GraphError::ComplexityBoundViolated { counter, observed, bound }.into()); }
    }
    Ok(())
}

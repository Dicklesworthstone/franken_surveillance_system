//! `ALG-MATCH-001` (weighted bipartite matching) and `ALG-MULTIMATCH-001` (k-best global
//! assignment).
//!
//! An [`AssignmentProblem`] has left items (tracks, tasks, observations), right items
//! (detections, workers, landmarks) and the *allowed* pairs with exact `u64` costs; a forbidden
//! pair is absent, never merely expensive. A [`NonAssignment`] policy prices leaving items
//! unassigned:
//!
//! * [`NonAssignment::MaximumCardinality`]: as many pairs as possible, then minimum total cost;
//! * [`NonAssignment::Priced`]: minimize pair costs plus a per-item price for every unassigned
//!   left and right item (the multi-hypothesis tracking "miss" and "birth" costs).
//!
//! Both reduce exactly to one square assignment over `N = L + R` rows (left items plus one
//! dummy row per right item) and columns (right items plus one private "unassigned" column per
//! left item), solved by the Hungarian algorithm in 128-bit arithmetic. Every solve certifies
//! itself: dual feasibility (no negative reduced cost) and complementary slackness on the
//! assignment prove optimality; a failure is `ERR-GRAPH-RESULT-INCONSISTENT-001`.
//!
//! Tie-break: among optimal assignments the answer is the lexicographically smallest
//! *assignment tuple* (left items in identity order; each maps to its right item's identity
//! index, unassigned sorting after every right item). Because every optimal assignment uses only
//! zero-reduced-cost entries of one optimal dual, the tuple is fixed greedily row by row over
//! that tight subgraph with alternating-path exchanges — exactly, not by perturbation.
//!
//! `ALG-MULTIMATCH-001` is Murty's partitioning over the left rows with a best-first queue keyed
//! by `(objective, assignment tuple)`; since each subproblem returns its own minimum under that
//! strict total order, the `k` answers are exactly the first `k` assignments in that order.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, VecDeque};

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::certified::{
    AlgorithmIdentity, BoundRow, Budget, CertifiedOutput, CertifiedRun, InputShape, Meter,
    OUTPUT_ENTRIES, add, checked_add, encode_ids, mul, query_digest, query_encoder,
};
use crate::graph::{GraphError, MAX_NODE_ID_LEN};

/// Assignment projection digest domain (`SCHEMA-DOMAIN-GRAPH-ASSIGNMENT-PROJECTION-001`).
pub const ASSIGNMENT_PROJECTION_DOMAIN: &str = "fss.graph.assignment_projection.v1";
/// `ALG-MATCH-001` output domain (`SCHEMA-DOMAIN-GRAPH-MATCH-OUTPUT-001`).
pub const MATCH_OUTPUT_DOMAIN: &str = "fss.graph.match_output.v1";
/// `ALG-MATCH-001` decision-path domain (`SCHEMA-DOMAIN-GRAPH-MATCH-DECISION-PATH-001`).
pub const MATCH_DECISION_PATH_DOMAIN: &str = "fss.graph.match_decision_path.v1";
/// `ALG-MULTIMATCH-001` output domain (`SCHEMA-DOMAIN-GRAPH-MULTIMATCH-OUTPUT-001`).
pub const MULTIMATCH_OUTPUT_DOMAIN: &str = "fss.graph.multimatch_output.v1";
/// `ALG-MULTIMATCH-001` decision-path domain (`SCHEMA-DOMAIN-GRAPH-MULTIMATCH-DECISION-PATH-001`).
pub const MULTIMATCH_DECISION_PATH_DOMAIN: &str = "fss.graph.multimatch_decision_path.v1";

/// Maximum items on one side.
pub const MAX_SIDE: usize = 128;
/// Maximum `k` of one k-best query.
pub const MAX_K: u32 = 256;

/// Registered identity (`ALG-MATCH-001`).
pub static MATCH_IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-MATCH-001",
    algorithm_name: "weighted_bipartite_matching",
    tie_break_rule: "weight then stable pair identity",
    complexity_witness: "augmentations or primal-dual updates",
    output_size_witness: "<= |V| / 2 matched pairs",
    exactness: "exact",
    implementation_id: "fss-graph-algorithms:alg-match-001:hungarian-i128-certified-lexmin-tight-subgraph:v1",
    tie_break_policy_id: "tie:objective-then-lexicographic-assignment-tuple-unassigned-last:v1",
    policy_id: "graph-policy:bipartite:allowed-pairs-only:nonassignment-maximum-cardinality-or-priced:numeric:u64-exact:checked:unit-bound:v1:tie:objective-then-lexicographic-assignment-tuple-unassigned-last:v1",
    complexity_bound_id: "bound:alg-match-001:hungarian-n-cubed-plus-lexmin-exchanges:v1",
    output_domain: MATCH_OUTPUT_DOMAIN,
    decision_path_domain: MATCH_DECISION_PATH_DOMAIN,
};

/// Registered identity (`ALG-MULTIMATCH-001`).
pub static MULTIMATCH_IDENTITY: AlgorithmIdentity = AlgorithmIdentity {
    algorithm_id: "ALG-MULTIMATCH-001",
    algorithm_name: "k_best_global_assignment",
    tie_break_rule: "score then canonical assignment tuple",
    complexity_witness: "branch nodes and matching solves",
    output_size_witness: "<= k * (|V| / 2) matched pairs",
    exactness: "bounded_exact",
    implementation_id: "fss-graph-algorithms:alg-multimatch-001:murty-best-first-lexmin-subproblems:v1",
    tie_break_policy_id: "tie:objective-then-lexicographic-assignment-tuple-unassigned-last:v1",
    policy_id: "graph-policy:bipartite:allowed-pairs-only:nonassignment-maximum-cardinality-or-priced:numeric:u64-exact:checked:unit-bound:v1:tie:objective-then-lexicographic-assignment-tuple-unassigned-last:v1",
    complexity_bound_id: "bound:alg-multimatch-001:murty-1-plus-k-n-solves:v1",
    output_domain: MULTIMATCH_OUTPUT_DOMAIN,
    decision_path_domain: MULTIMATCH_DECISION_PATH_DOMAIN,
};

fn per_solve(n: u64) -> [(&'static str, u64); 4] {
    [
        ("column_scans", mul(mul(n, n), add(n, 1))),
        ("potential_updates", mul(n, mul(add(n, 1), add(n, 1)))),
        ("swap_checks", mul(n, n)),
        ("alternating_scans", mul(mul(n, n), mul(n, n))),
    ]
}

/// The registered `ALG-MATCH-001` bound for `n = L + R` items and `m` allowed pairs.
#[must_use]
pub fn match_bound(n: u64, m: u64) -> Vec<BoundRow> {
    let mut rows: Vec<BoundRow> = vec![("solves", 1)];
    rows.extend(per_solve(n));
    rows.push(("certificate_checks", add(mul(n, n), m)));
    rows.push((OUTPUT_ENTRIES, n));
    rows
}

/// The registered `ALG-MULTIMATCH-001` bound for `n = L + R` items, `m` pairs and `k`.
#[must_use]
pub fn multimatch_bound(n: u64, m: u64, k: u64) -> Vec<BoundRow> {
    let solves = add(1, mul(k, n));
    let mut rows: Vec<BoundRow> = vec![("solves", solves), ("heap_operations", mul(2, solves))];
    rows.extend(per_solve(n).map(|(name, limit)| (name, mul(solves, limit))));
    rows.push(("certificate_checks", mul(solves, add(mul(n, n), m))));
    rows.push((OUTPUT_ENTRIES, mul(k, n)));
    rows
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_NODE_ID_LEN && !id.chars().any(char::is_control)
}

/// Collects one assignment problem in any order.
#[derive(Clone, Debug)]
pub struct AssignmentProblemBuilder {
    unit: String,
    left: Vec<String>,
    right: Vec<String>,
    pairs: Vec<(String, String, u64)>,
}

impl AssignmentProblemBuilder {
    /// An empty problem with every cost in `unit`.
    #[must_use]
    pub fn new(unit: impl Into<String>) -> Self {
        Self {
            unit: unit.into(),
            left: Vec::new(),
            right: Vec::new(),
            pairs: Vec::new(),
        }
    }

    /// Adds a left item.
    pub fn add_left(&mut self, id: impl Into<String>) -> &mut Self {
        self.left.push(id.into());
        self
    }

    /// Adds a right item.
    pub fn add_right(&mut self, id: impl Into<String>) -> &mut Self {
        self.right.push(id.into());
        self
    }

    /// Allows the pair `(left, right)` at `cost`.
    pub fn allow(
        &mut self,
        left: impl Into<String>,
        right: impl Into<String>,
        cost: u64,
    ) -> &mut Self {
        self.pairs.push((left.into(), right.into(), cost));
        self
    }

    /// Validates and canonicalizes.
    ///
    /// # Errors
    ///
    /// [`GraphError`] input variants for invalid or duplicate identities, unknown endpoints,
    /// duplicate pairs, an invalid unit, or more than [`MAX_SIDE`] items on a side.
    pub fn build(self) -> Result<AssignmentProblem, GraphError> {
        if self.unit.is_empty()
            || self.unit.len() > 64
            || !self
                .unit
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b":_-.".contains(&byte))
        {
            return Err(GraphError::InvalidNodeId(format!("unit:{}", self.unit)));
        }
        if self.left.len() > MAX_SIDE || self.right.len() > MAX_SIDE {
            return Err(GraphError::TooLarge);
        }
        let canonical = |mut ids: Vec<String>| -> Result<Vec<String>, GraphError> {
            ids.sort_unstable();
            for id in &ids {
                if !valid_id(id) {
                    return Err(GraphError::InvalidNodeId(id.clone()));
                }
            }
            for pair in ids.windows(2) {
                if pair[0] == pair[1] {
                    return Err(GraphError::DuplicateNode(pair[0].clone()));
                }
            }
            Ok(ids)
        };
        let left = canonical(self.left)?;
        let right = canonical(self.right)?;
        let find = |ids: &[String], id: &str| {
            ids.binary_search_by(|probe| probe.as_str().cmp(id))
                .map(|position| position as u32)
                .map_err(|_| GraphError::UnknownNode(id.to_owned()))
        };
        let mut pairs = Vec::with_capacity(self.pairs.len());
        for (l, r, cost) in &self.pairs {
            pairs.push((find(&left, l)?, find(&right, r)?, *cost));
        }
        pairs.sort_unstable();
        for pair in pairs.windows(2) {
            if (pair[0].0, pair[0].1) == (pair[1].0, pair[1].1) {
                return Err(GraphError::ParallelEdge(
                    left[pair[0].0 as usize].clone(),
                    right[pair[0].1 as usize].clone(),
                ));
            }
        }
        Ok(AssignmentProblem {
            unit: self.unit,
            left,
            right,
            pairs,
        })
    }
}

/// An immutable canonical assignment problem.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssignmentProblem {
    unit: String,
    left: Vec<String>,
    right: Vec<String>,
    pairs: Vec<(u32, u32, u64)>,
}

impl AssignmentProblem {
    /// Left items in canonical order.
    #[must_use]
    pub fn left(&self) -> &[String] {
        &self.left
    }

    /// Right items in canonical order.
    #[must_use]
    pub fn right(&self) -> &[String] {
        &self.right
    }

    /// Allowed pairs `(left index, right index, cost)` in canonical order.
    #[must_use]
    pub fn pairs(&self) -> &[(u32, u32, u64)] {
        &self.pairs
    }

    /// Cost of the allowed pair, if allowed.
    #[must_use]
    pub fn cost(&self, left: u32, right: u32) -> Option<u64> {
        self.pairs
            .binary_search_by(|&(l, r, _)| (l, r).cmp(&(left, right)))
            .ok()
            .map(|position| self.pairs[position].2)
    }

    /// Domain-separated canonical digest.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(ASSIGNMENT_PROJECTION_DOMAIN);
        encoder.text(&self.unit);
        encode_ids(&mut encoder, &self.left);
        encode_ids(&mut encoder, &self.right);
        encoder.u64(self.pairs.len() as u64);
        for &(l, r, cost) in &self.pairs {
            encoder.u32(l);
            encoder.u32(r);
            encoder.u64(cost);
        }
        ContentDigest::sha256(&encoder.finish())
    }
}

/// How unassigned items are priced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonAssignment {
    /// Maximize the number of pairs, then minimize their total cost.
    MaximumCardinality,
    /// Minimize pair costs plus `left` per unassigned left item and `right` per unassigned
    /// right item.
    Priced {
        /// Price of one unassigned left item.
        left: u64,
        /// Price of one unassigned right item.
        right: u64,
    },
}

impl NonAssignment {
    fn encode(self, encoder: &mut CanonicalEncoder) {
        match self {
            Self::MaximumCardinality => encoder.tag(0),
            Self::Priced { left, right } => {
                encoder.tag(1);
                encoder.u64(left);
                encoder.u64(right);
            }
        }
    }
}

/// One complete assignment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Assignment {
    /// `(left, right, cost)` ascending by left identity.
    pub pairs: Vec<(String, String, u64)>,
    /// Unassigned left items, ascending.
    pub unassigned_left: Vec<String>,
    /// Unassigned right items, ascending.
    pub unassigned_right: Vec<String>,
    /// Sum of pair costs.
    pub matched_cost: u64,
    /// Sum of non-assignment prices (zero under maximum cardinality).
    pub non_assignment_cost: u64,
    /// `matched_cost + non_assignment_cost`.
    pub objective: u64,
}

impl Assignment {
    fn entries(&self) -> u64 {
        (self.pairs.len() + self.unassigned_left.len() + self.unassigned_right.len()) as u64
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        encoder.u64(self.pairs.len() as u64);
        for (l, r, cost) in &self.pairs {
            encoder.text(l);
            encoder.text(r);
            encoder.u64(*cost);
        }
        encode_ids(encoder, &self.unassigned_left);
        encode_ids(encoder, &self.unassigned_right);
        encoder.u64(self.matched_cost);
        encoder.u64(self.non_assignment_cost);
        encoder.u64(self.objective);
    }
}

/// The canonical answer of `ALG-MATCH-001`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatchOutput {
    /// Non-assignment policy.
    pub policy: NonAssignment,
    /// The optimal assignment (smallest tuple among optima).
    pub assignment: Assignment,
}

impl CertifiedOutput for MatchOutput {
    fn entries(&self) -> u64 {
        self.assignment.entries()
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        self.policy.encode(encoder);
        self.assignment.encode(encoder);
    }
}

/// The canonical answer of `ALG-MULTIMATCH-001`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KBestOutput {
    /// Non-assignment policy.
    pub policy: NonAssignment,
    /// Requested `k`.
    pub requested: u32,
    /// The first `k` assignments in `(objective, tuple)` order.
    pub assignments: Vec<Assignment>,
    /// Fewer than `k` distinct assignments exist.
    pub exhausted: bool,
}

impl CertifiedOutput for KBestOutput {
    fn entries(&self) -> u64 {
        self.assignments.iter().map(Assignment::entries).sum()
    }

    fn encode(&self, encoder: &mut CanonicalEncoder) {
        self.policy.encode(encoder);
        encoder.u32(self.requested);
        encoder.u64(self.assignments.len() as u64);
        for assignment in &self.assignments {
            assignment.encode(encoder);
        }
        encoder.bool(self.exhausted);
    }
}

const FORBIDDEN: i128 = 1 << 100;
const INFINITE: i128 = i128::MAX / 4;

/// The square reduction: rows `0..L` left items, `L..L+R` dummy rows; columns `0..R` right
/// items, `R..R+L` private "unassigned" columns.
#[derive(Clone, Debug)]
struct Square {
    l: usize,
    r: usize,
    cost: Vec<Vec<i128>>,
}

impl Square {
    fn new(problem: &AssignmentProblem, policy: NonAssignment) -> Result<Self, GraphError> {
        let (l, r) = (problem.left.len(), problem.right.len());
        let n = l + r;
        let (left_price, right_price) = match policy {
            NonAssignment::MaximumCardinality => {
                let total: i128 = problem.pairs.iter().map(|&(_, _, c)| i128::from(c)).sum();
                (total + 1, total + 1)
            }
            NonAssignment::Priced { left, right } => (i128::from(left), i128::from(right)),
        };
        let mut cost = vec![vec![FORBIDDEN; n]; n];
        for &(li, ri, c) in &problem.pairs {
            cost[li as usize][ri as usize] = i128::from(c);
        }
        for (row, values) in cost.iter_mut().enumerate().take(l) {
            values[r + row] = left_price;
        }
        for values in cost.iter_mut().skip(l) {
            for (column, value) in values.iter_mut().enumerate() {
                *value = if column < r { right_price } else { 0 };
            }
        }
        if n > 0 && left_price >= FORBIDDEN / 4 {
            return Err(GraphError::ArithmeticOverflow("non-assignment price"));
        }
        Ok(Self { l, r, cost })
    }

    fn size(&self) -> usize {
        self.l + self.r
    }
}

/// One certified, lexicographically minimal optimum of a (constrained) square matrix.
struct Solved {
    objective: i128,
    /// Column of each row.
    row_column: Vec<usize>,
}

/// Hungarian algorithm (shortest augmenting paths with potentials), then the tight-subgraph
/// lexicographic minimization over the first `l` rows. `None` when infeasible.
fn solve(matrix: &[Vec<i128>], l: usize, meter: &mut Meter) -> Result<Option<Solved>, GraphError> {
    meter.tick("solves")?;
    let n = matrix.len();
    if n == 0 {
        return Ok(Some(Solved {
            objective: 0,
            row_column: Vec::new(),
        }));
    }
    let a = |i: usize, j: usize| matrix[i - 1][j - 1];
    let mut u = vec![0_i128; n + 1];
    let mut v = vec![0_i128; n + 1];
    let mut p = vec![0_usize; n + 1];
    let mut way = vec![0_usize; n + 1];
    for i in 1..=n {
        p[0] = i;
        let mut j0 = 0_usize;
        let mut minv = vec![INFINITE; n + 1];
        let mut used = vec![false; n + 1];
        loop {
            used[j0] = true;
            let i0 = p[j0];
            let mut delta = INFINITE;
            let mut j1 = 0_usize;
            for j in 1..=n {
                if !used[j] {
                    meter.tick("column_scans")?;
                    let current = a(i0, j) - u[i0] - v[j];
                    if current < minv[j] {
                        minv[j] = current;
                        way[j] = j0;
                    }
                    if minv[j] < delta {
                        delta = minv[j];
                        j1 = j;
                    }
                }
            }
            for j in 0..=n {
                meter.tick("potential_updates")?;
                if used[j] {
                    u[p[j]] += delta;
                    v[j] -= delta;
                } else {
                    minv[j] -= delta;
                }
            }
            j0 = j1;
            if p[j0] == 0 {
                break;
            }
        }
        loop {
            let j1 = way[j0];
            p[j0] = p[j1];
            j0 = j1;
            if j0 == 0 {
                break;
            }
        }
    }
    let mut row_column = vec![usize::MAX; n];
    let mut column_row = vec![usize::MAX; n];
    for j in 1..=n {
        row_column[p[j] - 1] = j - 1;
        column_row[j - 1] = p[j] - 1;
    }
    // Certificate: dual feasibility everywhere, complementary slackness on the assignment.
    let reduced = |i: usize, j: usize| matrix[i][j] - u[i + 1] - v[j + 1];
    for (i, &assigned) in row_column.iter().enumerate() {
        for j in 0..n {
            meter.tick("certificate_checks")?;
            if reduced(i, j) < 0 {
                return Err(GraphError::Inconsistent("negative reduced cost".to_owned()));
            }
        }
        if reduced(i, assigned) != 0 {
            return Err(GraphError::Inconsistent(
                "an assigned entry is not tight".to_owned(),
            ));
        }
    }
    if (0..n).any(|i| matrix[i][row_column[i]] >= FORBIDDEN) {
        return Ok(None);
    }
    let tight = |i: usize, j: usize| matrix[i][j] < FORBIDDEN && reduced(i, j) == 0;
    // Lexicographic minimization of the first l rows' columns over the tight subgraph; the
    // private column of row i (index n - l + i... i.e. r + i) sorts after every right column,
    // which is already its index order.
    for i in 0..l {
        let mut candidates: Vec<usize> = (0..n).filter(|&j| tight(i, j)).collect();
        candidates.sort_unstable();
        for &candidate in &candidates {
            if candidate == row_column[i] {
                break;
            }
            meter.tick("swap_checks")?;
            let holder = column_row[candidate];
            if holder < i {
                continue;
            }
            // Alternating path from `holder` to the column `i` frees, avoiding fixed rows and i.
            let freed = row_column[i];
            let mut from_row = vec![usize::MAX; n];
            let mut seen_row = vec![false; n];
            seen_row[holder] = true;
            let mut queue = VecDeque::from([holder]);
            let mut found = false;
            'search: while let Some(row) = queue.pop_front() {
                for column in 0..n {
                    meter.tick("alternating_scans")?;
                    if from_row[column] != usize::MAX || column == candidate || !tight(row, column)
                    {
                        continue;
                    }
                    from_row[column] = row;
                    if column == freed {
                        found = true;
                        break 'search;
                    }
                    let next = column_row[column];
                    if next > i && !seen_row[next] {
                        seen_row[next] = true;
                        queue.push_back(next);
                    }
                }
            }
            if found {
                let mut column = freed;
                loop {
                    let row = from_row[column];
                    let previous = row_column[row];
                    row_column[row] = column;
                    column_row[column] = row;
                    if row == holder {
                        break;
                    }
                    column = previous;
                }
                row_column[i] = candidate;
                column_row[candidate] = i;
                meter.decide(1, i as u64, candidate as u64);
                break;
            }
        }
    }
    let objective = (0..n).map(|i| matrix[i][row_column[i]]).sum();
    Ok(Some(Solved {
        objective,
        row_column,
    }))
}

fn render(
    problem: &AssignmentProblem,
    policy: NonAssignment,
    square: &Square,
    solved: &Solved,
) -> Result<Assignment, GraphError> {
    let (l, r) = (square.l, square.r);
    let mut pairs = Vec::new();
    let mut unassigned_left = Vec::new();
    let mut assigned_right = vec![false; r];
    let mut matched_cost = 0_u64;
    for i in 0..l {
        let column = solved.row_column[i];
        if column < r {
            let cost = problem.cost(i as u32, column as u32).ok_or_else(|| {
                GraphError::Inconsistent("a forbidden pair was assigned".to_owned())
            })?;
            matched_cost = checked_add(matched_cost, cost, "matched cost")?;
            assigned_right[column] = true;
            pairs.push((problem.left[i].clone(), problem.right[column].clone(), cost));
        } else {
            unassigned_left.push(problem.left[i].clone());
        }
    }
    let unassigned_right: Vec<String> = (0..r)
        .filter(|&j| !assigned_right[j])
        .map(|j| problem.right[j].clone())
        .collect();
    let non_assignment_cost = match policy {
        NonAssignment::MaximumCardinality => 0,
        NonAssignment::Priced { left, right } => checked_add(
            left.checked_mul(unassigned_left.len() as u64)
                .ok_or(GraphError::ArithmeticOverflow("non-assignment cost"))?,
            right
                .checked_mul(unassigned_right.len() as u64)
                .ok_or(GraphError::ArithmeticOverflow("non-assignment cost"))?,
            "non-assignment cost",
        )?,
    };
    Ok(Assignment {
        pairs,
        unassigned_left,
        unassigned_right,
        matched_cost,
        non_assignment_cost,
        objective: checked_add(matched_cost, non_assignment_cost, "assignment objective")?,
    })
}

fn input_digest(
    identity: &AlgorithmIdentity,
    problem: &AssignmentProblem,
    policy: NonAssignment,
    k: Option<u32>,
) -> ContentDigest {
    let mut input = query_encoder(identity, problem.digest());
    policy.encode(&mut input);
    if let Some(k) = k {
        input.u32(k);
    }
    query_digest(input)
}

/// Runs `ALG-MATCH-001`.
///
/// # Errors
///
/// [`GraphError::ArithmeticOverflow`] for costs outside `u64`, [`GraphError::Inconsistent`] when
/// the optimality certificate fails, and the fail-closed budget and bound errors.
pub fn optimal_assignment(
    problem: &AssignmentProblem,
    policy: NonAssignment,
    budget: Budget,
) -> Result<CertifiedRun<MatchOutput>, GraphError> {
    let square = Square::new(problem, policy)?;
    let mut meter = Meter::new(&MATCH_IDENTITY, budget);
    let solved = solve(&square.cost, square.l, &mut meter)?.ok_or_else(|| {
        GraphError::Inconsistent("the unconstrained reduction is infeasible".to_owned())
    })?;
    let assignment = render(problem, policy, &square, &solved)?;
    let n64 = square.size() as u64;
    let m64 = problem.pairs.len() as u64;
    meter.finish(
        &MATCH_IDENTITY,
        InputShape {
            node_count: n64,
            edge_count: m64,
            input_digest: input_digest(&MATCH_IDENTITY, problem, policy, None),
        },
        MatchOutput { policy, assignment },
        &match_bound(n64, m64),
        n64 * n64 * 16 + n64 * 64,
    )
}

/// One Murty subproblem: per left row an optional forced column and a forbidden column list.
#[derive(Clone, Debug)]
struct Constraints {
    forced: Vec<Option<usize>>,
    forbidden: Vec<Vec<usize>>,
}

impl Constraints {
    fn apply(&self, base: &[Vec<i128>]) -> Vec<Vec<i128>> {
        let mut matrix = base.to_vec();
        for (row, forced) in self.forced.iter().enumerate() {
            if let Some(column) = *forced {
                for (j, value) in matrix[row].iter_mut().enumerate() {
                    if j != column {
                        *value = FORBIDDEN;
                    }
                }
                for (i, values) in matrix.iter_mut().enumerate() {
                    if i != row {
                        values[column] = FORBIDDEN;
                    }
                }
            }
        }
        for (row, columns) in self.forbidden.iter().enumerate() {
            for &column in columns {
                matrix[row][column] = FORBIDDEN;
            }
        }
        matrix
    }
}

/// Runs `ALG-MULTIMATCH-001`: the first `k` assignments in `(objective, tuple)` order.
///
/// # Errors
///
/// [`GraphError::PreconditionFailed`] for `k = 0` or `k > MAX_K`, and every
/// [`optimal_assignment`] error.
pub fn k_best_assignments(
    problem: &AssignmentProblem,
    policy: NonAssignment,
    k: u32,
    budget: Budget,
) -> Result<CertifiedRun<KBestOutput>, GraphError> {
    if k == 0 || k > MAX_K {
        return Err(GraphError::PreconditionFailed(format!(
            "k must be within 1..={MAX_K}"
        )));
    }
    let square = Square::new(problem, policy)?;
    let (l, n) = (square.l, square.size());
    let mut meter = Meter::new(&MULTIMATCH_IDENTITY, budget);
    let tuple = |solved: &Solved| -> Vec<usize> { solved.row_column[..l].to_vec() };
    let mut nodes: Vec<(Constraints, Solved)> = Vec::new();
    let mut heap: BinaryHeap<Reverse<(i128, Vec<usize>, usize)>> = BinaryHeap::new();
    let root = Constraints {
        forced: vec![None; l],
        forbidden: vec![Vec::new(); l],
    };
    if let Some(solved) = solve(&root.apply(&square.cost), l, &mut meter)? {
        meter.tick("heap_operations")?;
        heap.push(Reverse((solved.objective, tuple(&solved), 0)));
        nodes.push((root, solved));
    }
    let mut assignments = Vec::new();
    while assignments.len() < k as usize {
        let Some(Reverse((_, _, index))) = heap.pop() else {
            break;
        };
        meter.tick("heap_operations")?;
        let (constraints, solved) = (nodes[index].0.clone(), &nodes[index].1);
        let chosen = tuple(solved);
        meter.decide(0, index as u64, assignments.len() as u64);
        assignments.push(render(problem, policy, &square, solved)?);
        if assignments.len() == k as usize {
            break;
        }
        let mut prefix = constraints.clone();
        for row in 0..l {
            if constraints.forced[row].is_some() {
                continue;
            }
            let mut child = prefix.clone();
            child.forbidden[row].push(chosen[row]);
            if let Some(solved) = solve(&child.apply(&square.cost), l, &mut meter)? {
                meter.tick("heap_operations")?;
                heap.push(Reverse((solved.objective, tuple(&solved), nodes.len())));
                nodes.push((child, solved));
            }
            prefix.forced[row] = Some(chosen[row]);
        }
    }
    let exhausted = assignments.len() < k as usize;
    let n64 = n as u64;
    let m64 = problem.pairs.len() as u64;
    meter.finish(
        &MULTIMATCH_IDENTITY,
        InputShape {
            node_count: n64,
            edge_count: m64,
            input_digest: input_digest(&MULTIMATCH_IDENTITY, problem, policy, Some(k)),
        },
        KBestOutput {
            policy,
            requested: k,
            assignments,
            exhausted,
        },
        &multimatch_bound(n64, m64, u64::from(k)),
        n64 * n64 * 16 * 2 + nodes.len() as u64 * (n64 * 8 + 64),
    )
}

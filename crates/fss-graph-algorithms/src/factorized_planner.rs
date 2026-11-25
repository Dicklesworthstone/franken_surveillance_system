#![forbid(unsafe_code)]
//! Factorized graph-relational query reference planner (`FSS-162`, `fss-x4a.23.12`).
//!
//! Composes [`ImmutableGraphProjection`] (`FSS-151`), [`crate::snapshot_view::GraphSnapshotCatalog`]
//! (`FSS-152`), and `ALG-FACTOR-001` [`crate::factorized_join::factorized_free_join`] with an
//! independent brute-force nested-loop relational join reference oracle to deliver a certified,
//! capability-projected, deterministic multiway graph-relational query planner:
//!
//! - **Capability-first projection binding:** operates exclusively over an already
//!   capability- and privacy-filtered [`ImmutableGraphProjection`], preserving its exact
//!   [`AbsenceBoundary`] (`CertifiedComplete` vs `UncertifiedOrRedacted`) so an empty join result
//!   over a redacted/gapped projection NEVER masquerades as certified absence!
//! - **Deterministic cardinality-ordered variable elimination:** chooses canonical variable
//!   elimination order strictly by `(distinct_domain_cardinality, -incident_predicate_degree,
//!   variable_name)` so reordering input predicates yields bit-identical query plans, plan
//!   digests, and materialized join tuples.
//! - **Exact reference differential oracle (`execute_reference_oracle`):** evaluates the exact
//!   same multiway pattern via independent nested-loop relation filtering so callers and tests
//!   can prove 100% tuple-set equivalence against `ALG-FACTOR-001` Leapfrog Triejoin.
//! - **Bounded checksummed binary receipt (`FSSFQP01` v1):** sealed under
//!   `fss.graph.factorized_query_plan.v1` binding projection generation, anchor, history root,
//!   elimination order, absence boundary, complexity witness digest, and tuple counts.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    LedgerAnchor,
};

use crate::certified::{Budget, CertifiedRun};
use crate::factorized_join::{
    FactorJoinOutput, FactorJoinProblem, PatternRelation, factorized_free_join,
};
use crate::projection::{
    AbsenceBoundary, GraphUniverse, ImmutableGraphProjection, ProjectionOrientation,
};

/// Registered digest domain for sealed [`FactorizedQueryPlanReceipt`] commitments (`FSS-162`).
pub const GRAPH_FACTORIZED_QUERY_PLAN_DOMAIN: &str = "fss.graph.factorized_query_plan.v1";
/// Binary wire header magic for serialized factorized query plan receipts.
pub const FACTORIZED_PLAN_MAGIC: [u8; 8] = *b"FSSFQP01";
/// Supported durable format version for [`FactorizedQueryPlanReceipt`].
pub const FACTORIZED_PLAN_VERSION: u32 = 1;
/// Hard ceiling on query variables in one planned multiway pattern (matches `ALG-FACTOR-001`).
pub const MAX_PLAN_VARIABLES: usize = 8;
/// Hard ceiling on binary relation predicates in one query pattern.
pub const MAX_PLAN_PREDICATES: usize = 32;
/// Hard ceiling on label bytes inside query predicates and receipts.
pub const MAX_PLAN_LABEL_BYTES: usize = 128;
/// Hard ceiling on serialized receipt wire bytes (512 KiB).
pub const MAX_PLAN_WIRE_BYTES: usize = 512 * 1024;

/// Safe operator/agent recovery guidance for a refused factorized query planner operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlannerGuidance {
    /// Fix invalid variable names, duplicate/self predicates, or weight bounds.
    RepairQueryPattern,
    /// Increase declared query budget or narrow relation filters before re-running.
    IncreaseBudgetOrNarrowPattern,
    /// Cooperative cancellation observed; safe to retry cleanly from pinned projection.
    RetryWhenReady,
    /// Reject corrupt or unsupported binary query plan receipt bytes.
    RejectCorruptReceipt,
}

/// Typed error returned by [`FactorizedQueryPlanner`] or [`FactorizedQueryPlanReceipt`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlannerError {
    /// Invalid variable set, predicate, weight range, or empty pattern.
    InvalidInput(String),
    /// Cooperative cancellation observed before completing planning or execution.
    Cancelled,
    /// Underlying `ALG-FACTOR-001` budget, complexity bound, or precondition failure.
    Execution(String),
    /// Variable count, predicate count, or wire length exceeded hard ceilings.
    BoundsExceeded {
        /// Observed size/count.
        observed: usize,
        /// Hard maximum.
        maximum: usize,
    },
    /// Binary receipt lacked [`FACTORIZED_PLAN_MAGIC`].
    InvalidMagic,
    /// Binary receipt declared an unsupported version.
    UnsupportedVersion {
        /// Observed version.
        version: u32,
    },
    /// Binary receipt was truncated, non-canonical, or structurally inconsistent.
    MalformedWire(String),
    /// Receipt canonical checksum failed verification.
    ChecksumMismatch,
    /// Canonical encoding failed.
    Encoding(String),
}

impl PlannerError {
    /// Stable canonical machine error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput(_) => "ERR-GRAPH-PLANNER-INVALID-INPUT-001",
            Self::Cancelled => "ERR-GRAPH-PLANNER-CANCELLED-001",
            Self::Execution(_) => "ERR-GRAPH-PLANNER-EXEC-001",
            Self::BoundsExceeded { .. } => "ERR-GRAPH-PLANNER-BOUNDS-001",
            Self::InvalidMagic => "ERR-GRAPH-PLANNER-INVALID-MAGIC-001",
            Self::UnsupportedVersion { .. } => "ERR-GRAPH-PLANNER-UNSUPPORTED-VERSION-001",
            Self::MalformedWire(_) => "ERR-GRAPH-PLANNER-MALFORMED-WIRE-001",
            Self::ChecksumMismatch => "ERR-GRAPH-PLANNER-CHECKSUM-MISMATCH-001",
            Self::Encoding(_) => "ERR-GRAPH-PLANNER-ENCODING-001",
        }
    }

    /// Safe recovery guidance.
    #[must_use]
    pub const fn guidance(&self) -> PlannerGuidance {
        match self {
            Self::InvalidInput(_) | Self::BoundsExceeded { .. } => {
                PlannerGuidance::RepairQueryPattern
            }
            Self::Execution(_) => PlannerGuidance::IncreaseBudgetOrNarrowPattern,
            Self::Cancelled => PlannerGuidance::RetryWhenReady,
            Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::MalformedWire(_)
            | Self::ChecksumMismatch
            | Self::Encoding(_) => PlannerGuidance::RejectCorruptReceipt,
        }
    }
}

impl fmt::Display for PlannerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl Error for PlannerError {}

/// One typed binary graph-relational predicate constraining `(left_var, right_var)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationPredicate {
    /// Human/machine predicate name (e.g. `"sees"`, `"adjacent"`).
    pub predicate_name: String,
    /// Source variable name in the query pattern.
    pub left_var: String,
    /// Target variable name in the query pattern (`left_var != right_var`).
    pub right_var: String,
    /// Optional exact edge relation label filter (`None` matches any visible edge relation).
    pub relation_filter: Option<String>,
    /// Inclusive minimum edge weight (`0` for unbounded lower).
    pub min_weight: u64,
    /// Inclusive maximum edge weight (`u64::MAX` for unbounded upper).
    pub max_weight: u64,
}

/// Multiway graph-relational query pattern over a capability-projected [`ImmutableGraphProjection`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphRelationalQuery {
    /// Stable query identity.
    pub query_id: String,
    /// Distinct query variable names (`1..=MAX_PLAN_VARIABLES`).
    pub variables: Vec<String>,
    /// Binary relation predicates (`1..=MAX_PLAN_PREDICATES`).
    pub predicates: Vec<RelationPredicate>,
}

/// Compiled, cardinality-ordered factorized query plan ready for `ALG-FACTOR-001`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactorizedQueryPlan {
    /// Stable query identity.
    pub query_id: String,
    /// Chosen deterministic variable elimination order.
    pub elimination_order: Vec<String>,
    /// Estimated domain cardinality per variable in elimination order.
    pub estimated_cardinalities: Vec<u64>,
    /// Compiled canonical [`FactorJoinProblem`] aligned to `elimination_order`.
    pub problem: FactorJoinProblem,
    /// Exact pinned projection digest.
    pub projection_digest: ContentDigest,
    /// Non-collapsed absence boundary inherited verbatim from the projection.
    pub absence_boundary: AbsenceBoundary,
    /// Canonical digest of this query plan.
    pub plan_digest: ContentDigest,
}

/// Executed plan outcome bundling certified `ALG-FACTOR-001` run, materialized tuples, and receipt.
#[derive(Clone, Debug)]
pub struct ExecutedFactorizedQuery {
    /// Compiled deterministic query plan.
    pub plan: FactorizedQueryPlan,
    /// Certified `ALG-FACTOR-001` execution with complexity witness and decision path digest.
    pub certified_run: CertifiedRun<FactorJoinOutput>,
    /// Complete joined tuples mapped back into caller's original `query.variables` column order,
    /// canonically sorted lexicographically.
    pub canonical_tuples: Vec<Vec<String>>,
    /// Sealed verifiable plan-and-execution receipt (`FSSFQP01` v1).
    pub receipt: FactorizedQueryPlanReceipt,
}

/// Sealed binary receipt certifying a planned and executed factorized graph-relational query (`FSSFQP01` v1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactorizedQueryPlanReceipt {
    /// Wire format version (`FACTORIZED_PLAN_VERSION`).
    pub format_version: u32,
    /// Stable query identity.
    pub query_id: String,
    /// Pinned graph universe label.
    pub universe: String,
    /// Pinned canonical ledger anchor.
    pub anchor: LedgerAnchor,
    /// Pinned canonical history-chain root.
    pub history_root: ContentDigest,
    /// Pinned projection digest (`FSS-151`).
    pub projection_digest: ContentDigest,
    /// Chosen deterministic variable elimination order.
    pub elimination_order: Vec<String>,
    /// Compiled plan digest.
    pub plan_digest: ContentDigest,
    /// `ALG-FACTOR-001` certified output digest.
    pub output_digest: ContentDigest,
    /// `ALG-FACTOR-001` certified decision-path digest.
    pub decision_path_digest: ContentDigest,
    /// Non-collapsed absence boundary (preserves redaction/coverage honesty on empty results!).
    pub absence_boundary: AbsenceBoundary,
    /// Number of complete variable bindings emitted.
    pub complete_bindings: u64,
    /// True iff `ALG-FACTOR-001` hit its registered `|V| * |Relations|` factor cap.
    pub capped: bool,
    /// Domain-separated SHA-256 commitment (`fss.graph.factorized_query_plan.v1`).
    pub receipt_digest: ContentDigest,
}

impl FactorizedQueryPlanReceipt {
    /// True iff an empty result can be honestly interpreted as certified absence (`CertifiedComplete` and `!capped`).
    #[must_use]
    pub const fn certifies_absence(&self) -> bool {
        matches!(
            self.absence_boundary,
            AbsenceBoundary::CertifiedComplete { .. }
        ) && !self.capped
    }

    /// Recomputes the domain-separated SHA-256 commitment (`fss.graph.factorized_query_plan.v1`).
    pub fn compute_digest(&self) -> Result<ContentDigest, PlannerError> {
        let mut enc = CanonicalEncoder::new();
        enc.text(GRAPH_FACTORIZED_QUERY_PLAN_DOMAIN);
        self.encode_body(&mut enc);
        let bytes = enc
            .finish_checked()
            .map_err(|e| PlannerError::Encoding(e.to_string()))?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Verifies structural bounds, distinct elimination variables, and cryptographic self-digest.
    pub fn verify_self(&self) -> Result<(), PlannerError> {
        if self.format_version != FACTORIZED_PLAN_VERSION {
            return Err(PlannerError::UnsupportedVersion {
                version: self.format_version,
            });
        }
        validate_label(&self.query_id, MAX_PLAN_LABEL_BYTES, "query_id")
            .map_err(|e| PlannerError::MalformedWire(e.to_string()))?;
        validate_label(&self.universe, MAX_PLAN_LABEL_BYTES, "universe")
            .map_err(|e| PlannerError::MalformedWire(e.to_string()))?;
        if !is_registered_universe(&self.universe) {
            return Err(PlannerError::MalformedWire(format!(
                "unregistered graph universe '{}'",
                self.universe
            )));
        }
        if self.elimination_order.is_empty() || self.elimination_order.len() > MAX_PLAN_VARIABLES {
            return Err(PlannerError::BoundsExceeded {
                observed: self.elimination_order.len(),
                maximum: MAX_PLAN_VARIABLES,
            });
        }
        let mut seen = BTreeSet::new();
        for v in &self.elimination_order {
            validate_label(v, MAX_PLAN_LABEL_BYTES, "elimination_var")
                .map_err(|e| PlannerError::MalformedWire(e.to_string()))?;
            if !seen.insert(v.as_str()) {
                return Err(PlannerError::MalformedWire(
                    "duplicate variable in elimination_order".to_owned(),
                ));
            }
        }
        if self.compute_digest()? != self.receipt_digest {
            return Err(PlannerError::ChecksumMismatch);
        }
        Ok(())
    }

    fn encode_body(&self, enc: &mut CanonicalEncoder) {
        enc.u32(self.format_version);
        enc.text(&self.query_id);
        enc.text(&self.universe);
        self.anchor.encode_canonical(enc);
        enc.digest(self.history_root);
        enc.digest(self.projection_digest);
        enc.u32(self.elimination_order.len() as u32);
        for v in &self.elimination_order {
            enc.text(v);
        }
        enc.digest(self.plan_digest);
        enc.digest(self.output_digest);
        enc.digest(self.decision_path_digest);
        self.absence_boundary.encode_canonical(enc);
        enc.u64(self.complete_bindings);
        enc.bool(self.capped);
    }

    /// Encodes this receipt into bounded checksummed binary bytes (`FSSFQP01` v1).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, PlannerError> {
        self.verify_self()?;
        let mut enc = CanonicalEncoder::new();
        self.encode_body(&mut enc);
        enc.digest(self.receipt_digest);
        let body = enc
            .finish_checked()
            .map_err(|e| PlannerError::Encoding(e.to_string()))?;
        let total = FACTORIZED_PLAN_MAGIC
            .len()
            .saturating_add(4)
            .saturating_add(body.len());
        if total > MAX_PLAN_WIRE_BYTES {
            return Err(PlannerError::BoundsExceeded {
                observed: total,
                maximum: MAX_PLAN_WIRE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&FACTORIZED_PLAN_MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Cold-decodes and verifies a binary [`FactorizedQueryPlanReceipt`] (`FSSFQP01` v1).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PlannerError> {
        if bytes.len() > MAX_PLAN_WIRE_BYTES {
            return Err(PlannerError::BoundsExceeded {
                observed: bytes.len(),
                maximum: MAX_PLAN_WIRE_BYTES,
            });
        }
        if bytes.len() < 12 || bytes[..8] != FACTORIZED_PLAN_MAGIC {
            return Err(PlannerError::InvalidMagic);
        }
        let header_ver = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if header_ver != FACTORIZED_PLAN_VERSION {
            return Err(PlannerError::UnsupportedVersion {
                version: header_ver,
            });
        }
        let mut dec = CanonicalDecoder::new(&bytes[12..]);
        let format_version = dec
            .u32()
            .map_err(|e| PlannerError::MalformedWire(e.to_string()))?;
        if format_version != header_ver {
            return Err(PlannerError::UnsupportedVersion {
                version: format_version,
            });
        }
        let query_id = dec
            .text()
            .map_err(|e| PlannerError::MalformedWire(e.to_string()))?
            .to_owned();
        let universe = dec
            .text()
            .map_err(|e| PlannerError::MalformedWire(e.to_string()))?
            .to_owned();
        let anchor = LedgerAnchor::decode_canonical(&mut dec)
            .map_err(|e| PlannerError::MalformedWire(e.to_string()))?;
        let history_root = dec
            .digest()
            .map_err(|e| PlannerError::MalformedWire(e.to_string()))?;
        let projection_digest = dec
            .digest()
            .map_err(|e| PlannerError::MalformedWire(e.to_string()))?;
        let var_count =
            dec.u32()
                .map_err(|e| PlannerError::MalformedWire(e.to_string()))? as usize;
        if var_count == 0 || var_count > MAX_PLAN_VARIABLES {
            return Err(PlannerError::BoundsExceeded {
                observed: var_count,
                maximum: MAX_PLAN_VARIABLES,
            });
        }
        if var_count.saturating_mul(5) > dec.remaining() {
            return Err(PlannerError::MalformedWire(
                "truncated elimination_order in factorized plan receipt".to_owned(),
            ));
        }
        let mut elimination_order = Vec::with_capacity(var_count);
        for _ in 0..var_count {
            elimination_order.push(
                dec.text()
                    .map_err(|e| PlannerError::MalformedWire(e.to_string()))?
                    .to_owned(),
            );
        }
        let plan_digest = dec
            .digest()
            .map_err(|e| PlannerError::MalformedWire(e.to_string()))?;
        let output_digest = dec
            .digest()
            .map_err(|e| PlannerError::MalformedWire(e.to_string()))?;
        let decision_path_digest = dec
            .digest()
            .map_err(|e| PlannerError::MalformedWire(e.to_string()))?;
        let absence_boundary = AbsenceBoundary::decode_canonical(&mut dec)
            .map_err(|e| PlannerError::MalformedWire(e.to_string()))?;
        let complete_bindings = dec
            .u64()
            .map_err(|e| PlannerError::MalformedWire(e.to_string()))?;
        let capped = dec
            .bool()
            .map_err(|e| PlannerError::MalformedWire(e.to_string()))?;
        let stored_digest = dec
            .digest()
            .map_err(|e| PlannerError::MalformedWire(e.to_string()))?;
        dec.ensure_finished().map_err(|_| {
            PlannerError::MalformedWire("trailing bytes after factorized plan receipt".to_owned())
        })?;

        let receipt = Self {
            format_version,
            query_id,
            universe,
            anchor,
            history_root,
            projection_digest,
            elimination_order,
            plan_digest,
            output_digest,
            decision_path_digest,
            absence_boundary,
            complete_bindings,
            capped,
            receipt_digest: stored_digest,
        };
        receipt.verify_self()?;
        Ok(receipt)
    }
}

/// Deterministic factorized graph-relational query planner and differential oracle (`FSS-162`).
pub struct FactorizedQueryPlanner;

impl FactorizedQueryPlanner {
    /// Compiles `query` against a capability-projected [`ImmutableGraphProjection`] into a
    /// submission-order-invariant, cardinality-ordered [`FactorizedQueryPlan`].
    pub fn plan(
        projection: &ImmutableGraphProjection,
        query: &GraphRelationalQuery,
        cancelled: bool,
    ) -> Result<FactorizedQueryPlan, PlannerError> {
        if cancelled {
            return Err(PlannerError::Cancelled);
        }
        validate_query(query)?;

        let node_ids: Vec<String> = projection
            .node_handles()
            .into_iter()
            .map(|h| {
                projection
                    .node(h)
                    .map(|n| n.node_id.clone())
                    .map_err(|e| PlannerError::Execution(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Materialize each predicate's filtered sorted pair set over ONLY visible authorized edges!
        // Compute tight domain cardinality per variable as the commutative intersection across
        // all incident predicates (so an empty incident predicate immediately gets cardinality 0!).
        let mut pred_pairs: Vec<(&RelationPredicate, Vec<(String, String)>)> =
            Vec::with_capacity(query.predicates.len());
        let mut var_domain_sets: BTreeMap<&str, Option<BTreeSet<String>>> = BTreeMap::new();
        let mut var_degrees: BTreeMap<&str, usize> = BTreeMap::new();
        for v in &query.variables {
            var_domain_sets.insert(v.as_str(), None);
            var_degrees.insert(v.as_str(), 0);
        }

        for pred in &query.predicates {
            let mut pairs = Vec::new();
            for handle in projection.edge_handles() {
                let edge = projection
                    .edge(handle)
                    .map_err(|e| PlannerError::Execution(e.to_string()))?;
                if let Some(ref rel) = pred.relation_filter
                    && edge.relation != *rel
                {
                    continue;
                }
                if edge.weight < pred.min_weight || edge.weight > pred.max_weight {
                    continue;
                }
                let u = node_ids[edge.source_index as usize].clone();
                let v = node_ids[edge.target_index as usize].clone();
                pairs.push((u.clone(), v.clone()));
                if projection.orientation() == ProjectionOrientation::Undirected {
                    pairs.push((v, u));
                }
            }
            pairs.sort();
            pairs.dedup();
            let mut left_vals = BTreeSet::new();
            let mut right_vals = BTreeSet::new();
            for (a, b) in &pairs {
                left_vals.insert(a.clone());
                right_vals.insert(b.clone());
            }
            if let Some(slot) = var_domain_sets.get_mut(pred.left_var.as_str()) {
                match slot {
                    Some(existing) => existing.retain(|x| left_vals.contains(x)),
                    None => *slot = Some(left_vals),
                }
            }
            if let Some(slot) = var_domain_sets.get_mut(pred.right_var.as_str()) {
                match slot {
                    Some(existing) => existing.retain(|x| right_vals.contains(x)),
                    None => *slot = Some(right_vals),
                }
            }
            *var_degrees.entry(pred.left_var.as_str()).or_default() += 1;
            *var_degrees.entry(pred.right_var.as_str()).or_default() += 1;
            pred_pairs.push((pred, pairs));
        }

        // Deterministic cardinality-first variable elimination order (CGSE tie-break):
        // smallest distinct domain cardinality -> highest incident degree -> ascending variable name!
        let mut ranked_vars: Vec<(u64, usize, String)> = query
            .variables
            .iter()
            .map(|v| {
                let deg = var_degrees.get(v.as_str()).copied().unwrap_or(0);
                let card = if deg == 0 {
                    node_ids.len() as u64
                } else {
                    var_domain_sets
                        .get(v.as_str())
                        .and_then(Option::as_ref)
                        .map_or(0, |s| s.len() as u64)
                };
                (card, deg, v.clone())
            })
            .collect();
        ranked_vars.sort_by(|a, b| {
            (a.0, std::cmp::Reverse(a.1), a.2.as_str()).cmp(&(
                b.0,
                std::cmp::Reverse(b.1),
                b.2.as_str(),
            ))
        });

        let elimination_order: Vec<String> = ranked_vars.iter().map(|r| r.2.clone()).collect();
        let estimated_cardinalities: Vec<u64> = ranked_vars.iter().map(|r| r.0).collect();
        let pos_of: BTreeMap<&str, usize> = elimination_order
            .iter()
            .enumerate()
            .map(|(i, v)| (v.as_str(), i))
            .collect();

        // Orient every binary predicate so `left_var < right_var` in `elimination_order`!
        let mut relations: Vec<PatternRelation> = Vec::with_capacity(pred_pairs.len());
        for (pred, mut pairs) in pred_pairs {
            let p_left = pos_of[pred.left_var.as_str()];
            let p_right = pos_of[pred.right_var.as_str()];
            let (left_var, right_var) = if p_left < p_right {
                (p_left, p_right)
            } else {
                for pair in &mut pairs {
                    std::mem::swap(&mut pair.0, &mut pair.1);
                }
                pairs.sort();
                pairs.dedup();
                (p_right, p_left)
            };
            relations.push(PatternRelation {
                name: pred.predicate_name.clone(),
                left_var,
                right_var,
                pairs,
            });
        }
        // Sort compiled relations canonically so predicate submission order NEVER changes plan_digest!
        relations.sort_by(|a, b| {
            (a.left_var, a.right_var, a.name.as_str())
                .cmp(&(b.left_var, b.right_var, b.name.as_str()))
                .then_with(|| a.pairs.cmp(&b.pairs))
        });

        let problem = FactorJoinProblem {
            variables: elimination_order.clone(),
            domain: node_ids,
            relations,
        };
        let projection_digest = projection.generation().projection_digest;
        let absence_boundary = projection.absence_boundary().clone();

        let mut enc = CanonicalEncoder::new();
        enc.text(GRAPH_FACTORIZED_QUERY_PLAN_DOMAIN);
        enc.text("plan");
        enc.text(&query.query_id);
        enc.digest(projection_digest);
        enc.u32(elimination_order.len() as u32);
        for v in &elimination_order {
            enc.text(v);
        }
        enc.digest(problem.digest());
        absence_boundary.encode_canonical(&mut enc);
        let plan_digest = ContentDigest::sha256(
            &enc.finish_checked()
                .map_err(|e| PlannerError::Encoding(e.to_string()))?,
        );

        Ok(FactorizedQueryPlan {
            query_id: query.query_id.clone(),
            elimination_order,
            estimated_cardinalities,
            problem,
            projection_digest,
            absence_boundary,
            plan_digest,
        })
    }

    /// Plans and executes `query` over `projection` using `ALG-FACTOR-001` (`factorized_free_join`),
    /// returning materialized tuples in caller's variable order plus a sealed [`FactorizedQueryPlanReceipt`].
    pub fn plan_and_execute(
        projection: &ImmutableGraphProjection,
        query: &GraphRelationalQuery,
        budget: Budget,
        cancelled: bool,
    ) -> Result<ExecutedFactorizedQuery, PlannerError> {
        let plan = Self::plan(projection, query, cancelled)?;
        if cancelled {
            return Err(PlannerError::Cancelled);
        }
        let certified_run = factorized_free_join(&plan.problem, budget)
            .map_err(|e| PlannerError::Execution(e.to_string()))?;

        // Project materialized tuples from `plan.elimination_order` back to `query.variables` order.
        let elim_pos: BTreeMap<&str, usize> = plan
            .elimination_order
            .iter()
            .enumerate()
            .map(|(i, v)| (v.as_str(), i))
            .collect();
        let raw_tuples = certified_run
            .output
            .materialize_tuples(plan.elimination_order.len());
        let mut canonical_tuples: Vec<Vec<String>> = raw_tuples
            .into_iter()
            .map(|row| {
                query
                    .variables
                    .iter()
                    .map(|v| row[elim_pos[v.as_str()]].clone())
                    .collect()
            })
            .collect();
        canonical_tuples.sort();
        canonical_tuples.dedup();

        let mut receipt = FactorizedQueryPlanReceipt {
            format_version: FACTORIZED_PLAN_VERSION,
            query_id: query.query_id.clone(),
            universe: universe_label(projection.universe()).to_owned(),
            anchor: projection.anchor().clone(),
            history_root: projection.history_root(),
            projection_digest: plan.projection_digest,
            elimination_order: plan.elimination_order.clone(),
            plan_digest: plan.plan_digest,
            output_digest: certified_run.output_digest,
            decision_path_digest: certified_run.decision_path_digest,
            absence_boundary: plan.absence_boundary.clone(),
            complete_bindings: certified_run.output.complete_bindings,
            capped: certified_run.output.capped,
            receipt_digest: ContentDigest::sha256(b"unsealed-factorized-plan-receipt"),
        };
        receipt.receipt_digest = receipt.compute_digest()?;
        receipt.verify_self()?;

        Ok(ExecutedFactorizedQuery {
            plan,
            certified_run,
            canonical_tuples,
            receipt,
        })
    }

    /// Independent brute-force backtracking reference oracle for differential verification against
    /// `ALG-FACTOR-001` (`plan_and_execute`). Evaluates `query` over `projection` without using
    /// Leapfrog Triejoin or variable reordering and returns exact sorted tuples in `query.variables` order.
    pub fn execute_reference_oracle(
        projection: &ImmutableGraphProjection,
        query: &GraphRelationalQuery,
        max_tuples: usize,
        cancelled: bool,
    ) -> Result<Vec<Vec<String>>, PlannerError> {
        if cancelled {
            return Err(PlannerError::Cancelled);
        }
        validate_query(query)?;

        let node_ids: Vec<String> = projection
            .node_handles()
            .into_iter()
            .map(|h| {
                projection
                    .node(h)
                    .map(|n| n.node_id.clone())
                    .map_err(|e| PlannerError::Execution(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let var_pos: BTreeMap<&str, usize> = query
            .variables
            .iter()
            .enumerate()
            .map(|(i, v)| (v.as_str(), i))
            .collect();

        let mut pred_sets: Vec<OraclePredicateSet> = Vec::with_capacity(query.predicates.len());
        for pred in &query.predicates {
            let mut set = BTreeSet::new();
            for handle in projection.edge_handles() {
                let edge = projection
                    .edge(handle)
                    .map_err(|e| PlannerError::Execution(e.to_string()))?;
                if let Some(ref rel) = pred.relation_filter
                    && edge.relation != *rel
                {
                    continue;
                }
                if edge.weight < pred.min_weight || edge.weight > pred.max_weight {
                    continue;
                }
                let u = node_ids[edge.source_index as usize].clone();
                let v = node_ids[edge.target_index as usize].clone();
                set.insert((u.clone(), v.clone()));
                if projection.orientation() == ProjectionOrientation::Undirected {
                    set.insert((v, u));
                }
            }
            pred_sets.push((
                var_pos[pred.left_var.as_str()],
                var_pos[pred.right_var.as_str()],
                set,
            ));
        }

        let arity = query.variables.len();
        let mut assignment: Vec<String> = Vec::with_capacity(arity);
        let mut results: Vec<Vec<String>> = Vec::new();
        backtrack_oracle(
            0,
            arity,
            &node_ids,
            &pred_sets,
            &mut assignment,
            &mut results,
            max_tuples,
        )?;
        results.sort();
        results.dedup();
        Ok(results)
    }
}

type OraclePredicateSet = (usize, usize, BTreeSet<(String, String)>);

fn backtrack_oracle(
    depth: usize,
    arity: usize,
    domain: &[String],
    pred_sets: &[OraclePredicateSet],
    assignment: &mut Vec<String>,
    results: &mut Vec<Vec<String>>,
    max_tuples: usize,
) -> Result<(), PlannerError> {
    if depth == arity {
        if results.len() >= max_tuples {
            return Err(PlannerError::BoundsExceeded {
                observed: results.len().saturating_add(1),
                maximum: max_tuples,
            });
        }
        results.push(assignment.clone());
        return Ok(());
    }
    for val in domain {
        assignment.push(val.clone());
        let ok = pred_sets.iter().all(|(l, r, set)| {
            if *l <= depth && *r <= depth {
                set.contains(&(assignment[*l].clone(), assignment[*r].clone()))
            } else {
                true
            }
        });
        if ok {
            backtrack_oracle(
                depth + 1,
                arity,
                domain,
                pred_sets,
                assignment,
                results,
                max_tuples,
            )?;
        }
        assignment.pop();
    }
    Ok(())
}

fn validate_query(query: &GraphRelationalQuery) -> Result<(), PlannerError> {
    validate_label(&query.query_id, MAX_PLAN_LABEL_BYTES, "query_id")?;
    if query.variables.is_empty() || query.variables.len() > MAX_PLAN_VARIABLES {
        return Err(PlannerError::BoundsExceeded {
            observed: query.variables.len(),
            maximum: MAX_PLAN_VARIABLES,
        });
    }
    if query.predicates.is_empty() || query.predicates.len() > MAX_PLAN_PREDICATES {
        return Err(PlannerError::BoundsExceeded {
            observed: query.predicates.len(),
            maximum: MAX_PLAN_PREDICATES,
        });
    }
    let mut vars = BTreeSet::new();
    for v in &query.variables {
        validate_label(v, MAX_PLAN_LABEL_BYTES, "variable")?;
        if !vars.insert(v.as_str()) {
            return Err(PlannerError::InvalidInput(format!(
                "duplicate variable '{v}'"
            )));
        }
    }
    for p in &query.predicates {
        validate_label(&p.predicate_name, MAX_PLAN_LABEL_BYTES, "predicate_name")?;
        if !vars.contains(p.left_var.as_str()) || !vars.contains(p.right_var.as_str()) {
            return Err(PlannerError::InvalidInput(format!(
                "predicate '{}' references undeclared variable",
                p.predicate_name
            )));
        }
        if p.left_var == p.right_var {
            return Err(PlannerError::InvalidInput(format!(
                "predicate '{}' cannot constrain a variable against itself",
                p.predicate_name
            )));
        }
        if let Some(ref rel) = p.relation_filter {
            validate_label(rel, MAX_PLAN_LABEL_BYTES, "relation_filter")?;
        }
        if p.min_weight > p.max_weight {
            return Err(PlannerError::InvalidInput(format!(
                "predicate '{}' has min_weight > max_weight",
                p.predicate_name
            )));
        }
    }
    Ok(())
}

const fn universe_label(u: GraphUniverse) -> &'static str {
    u.as_str()
}

fn is_registered_universe(label: &str) -> bool {
    matches!(
        label,
        "G_phys"
            | "H_vis"
            | "G_sensor"
            | "G_time"
            | "G_assoc"
            | "G_evidence"
            | "G_effect"
            | "G_object"
            | "G_auth"
            | "G_memory"
            | "G_agent"
            | "G_world"
    )
}

fn validate_label(value: &str, max_len: usize, label: &str) -> Result<(), PlannerError> {
    if value.is_empty() || value.len() > max_len {
        return Err(PlannerError::InvalidInput(format!(
            "{label} length {} outside 1..={max_len}",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(PlannerError::InvalidInput(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}

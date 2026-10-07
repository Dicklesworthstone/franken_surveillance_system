//! Shared certification machinery of the registered weighted and directed algorithm families.
//!
//! Every family in this crate follows one contract (`GRAPH-INV-003`, `GRAPH-INV-008`):
//!
//! * a registered [`AlgorithmIdentity`] whose fields equal the machine registry row
//!   (`architecture/graph_algorithms.json`, checked by each family's certification test);
//! * a [`Meter`] that charges every dominant operation against a declared [`Budget`] and fails
//!   closed with [`GraphError::BudgetExhausted`] — never a partial answer;
//! * after the run, every observed counter and the output size are checked against the
//!   registered complexity bound for the exact input size ([`BoundRow`]); a violation is
//!   [`GraphError::ComplexityBoundViolated`] and nothing is returned;
//! * a [`CertifiedRun`] carrying the answer, the domain-separated output and decision-path
//!   digests, and the [`GraphAlgorithmWitness`] constructor;
//! * [`check_witness`] re-checks a stored witness against the bound recomputed from its own
//!   `n` and `m`, so a tampered or regressed witness is refused.
//!
//! Nothing here reads a clock, the filesystem, or the network, and no output grants authority.

use std::collections::BTreeMap;

use fss_core::{
    CanonicalEncoder, ContentDigest, ContractError, GraphAlgorithmWitness,
    GraphAlgorithmWitnessParams, LedgerAnchor,
};

use crate::graph::GraphError;

/// Name of the output-size row of every bound.
pub const OUTPUT_ENTRIES: &str = "output_entries";
/// Query input digest domain (`SCHEMA-DOMAIN-GRAPH-QUERY-INPUT-001`): binds the algorithm
/// identity, the projection digest and every query parameter (root, source, sink, k, policy).
pub const QUERY_INPUT_DOMAIN: &str = "fss.graph.query_input.v1";

/// Starts the canonical query input of `identity` over a projection with `projection_digest`;
/// the caller appends every query parameter and passes the finished digest as the witness's
/// `inputDigest`.
#[must_use]
pub fn query_encoder(
    identity: &AlgorithmIdentity,
    projection_digest: ContentDigest,
) -> CanonicalEncoder {
    let mut encoder = CanonicalEncoder::new();
    encoder.text(QUERY_INPUT_DOMAIN);
    encoder.text(identity.algorithm_id);
    encoder.text(identity.implementation_id);
    encoder.text(&projection_digest.to_text());
    encoder
}

/// Seals a query input encoder.
#[must_use]
pub fn query_digest(encoder: CanonicalEncoder) -> ContentDigest {
    ContentDigest::sha256(&encoder.finish())
}

/// The registered identity of one implemented algorithm row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlgorithmIdentity {
    /// Registered algorithm identity (`ALG-...`).
    pub algorithm_id: &'static str,
    /// Registered algorithm name.
    pub algorithm_name: &'static str,
    /// Registered tie-break rule text.
    pub tie_break_rule: &'static str,
    /// Registered complexity-witness text.
    pub complexity_witness: &'static str,
    /// Registered output-size witness text.
    pub output_size_witness: &'static str,
    /// Registered exactness class.
    pub exactness: &'static str,
    /// Implementation generation carried by every witness.
    pub implementation_id: &'static str,
    /// Canonical tie-break policy identity.
    pub tie_break_policy_id: &'static str,
    /// Graph policy identity (orientation, multiplicity, numeric and tie-break policy).
    pub policy_id: &'static str,
    /// Complexity bound identity.
    pub complexity_bound_id: &'static str,
    /// Output digest domain.
    pub output_domain: &'static str,
    /// Decision-path digest domain.
    pub decision_path_domain: &'static str,
}

impl AlgorithmIdentity {
    /// `(registry field, implemented value)` pairs a certification test compares with the
    /// machine registry row.
    #[must_use]
    pub fn registry_fields(&self) -> [(&'static str, &'static str); 11] {
        [
            ("id", self.algorithm_id),
            ("name", self.algorithm_name),
            ("tieBreak", self.tie_break_rule),
            ("complexityWitness", self.complexity_witness),
            ("outputSizeWitness", self.output_size_witness),
            ("exactness", self.exactness),
            ("status", "implemented"),
            ("implementationId", self.implementation_id),
            ("tieBreakPolicyId", self.tie_break_policy_id),
            ("policyId", self.policy_id),
            ("complexityBoundId", self.complexity_bound_id),
        ]
    }
}

/// One registered bound: `counter <= limit` for the run's input size.
pub type BoundRow = (&'static str, u64);

/// Declared resource budget of one run; exhaustion fails closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Budget {
    /// Maximum charged dominant operations.
    pub max_operations: u64,
    /// Maximum emitted output entries.
    pub max_output_entries: u64,
}

impl Budget {
    /// An explicit budget.
    #[must_use]
    pub const fn new(max_operations: u64, max_output_entries: u64) -> Self {
        Self {
            max_operations,
            max_output_entries,
        }
    }

    /// The budget an exact run within `bound` can never exceed: the sum of every operation
    /// counter bound and the output-entries bound.
    #[must_use]
    pub fn registered(bound: &[BoundRow]) -> Self {
        let mut operations = 0_u64;
        let mut output = 0_u64;
        for &(counter, limit) in bound {
            if counter == OUTPUT_ENTRIES {
                output = limit;
            } else {
                operations = operations.saturating_add(limit);
            }
        }
        Self::new(operations, output)
    }
}

/// Charges dominant operations against a budget and records the decision path.
#[derive(Debug)]
pub struct Meter {
    budget: Budget,
    operations: u64,
    counters: BTreeMap<&'static str, u64>,
    path: CanonicalEncoder,
}

impl Meter {
    /// A fresh meter whose decision path starts with the identity's domain and tie-break policy.
    #[must_use]
    pub fn new(identity: &AlgorithmIdentity, budget: Budget) -> Self {
        let mut path = CanonicalEncoder::new();
        path.text(identity.decision_path_domain);
        path.text(identity.tie_break_policy_id);
        Self {
            budget,
            operations: 0,
            counters: BTreeMap::new(),
            path,
        }
    }

    /// Charges one operation to `counter`.
    ///
    /// # Errors
    ///
    /// [`GraphError::BudgetExhausted`] when the operation budget is spent.
    pub fn tick(&mut self, counter: &'static str) -> Result<(), GraphError> {
        self.tick_n(counter, 1)
    }

    /// Charges `count` operations to `counter`.
    ///
    /// # Errors
    ///
    /// [`GraphError::BudgetExhausted`] when the operation budget is spent.
    pub fn tick_n(&mut self, counter: &'static str, count: u64) -> Result<(), GraphError> {
        *self.counters.entry(counter).or_insert(0) += count;
        self.operations = self.operations.saturating_add(count);
        if self.operations > self.budget.max_operations {
            return Err(GraphError::BudgetExhausted {
                dimension: "operations",
                limit: self.budget.max_operations,
            });
        }
        Ok(())
    }

    /// Operations charged so far.
    #[must_use]
    pub const fn operations(&self) -> u64 {
        self.operations
    }

    /// The decision-path encoder (record every tie-relevant choice in order).
    pub fn path(&mut self) -> &mut CanonicalEncoder {
        &mut self.path
    }

    /// Records one tagged decision with two indices.
    pub fn decide(&mut self, tag: u8, first: u64, second: u64) {
        self.path.tag(tag);
        self.path.u64(first);
        self.path.u64(second);
    }

    /// Checks the run against `bound` and seals it.
    ///
    /// # Errors
    ///
    /// [`GraphError::BudgetExhausted`] for output entries above the budget,
    /// [`GraphError::ComplexityBoundViolated`] for any counter (or the output size) above its
    /// bound or a counter that has no registered bound.
    pub fn finish<O: CertifiedOutput>(
        self,
        identity: &'static AlgorithmIdentity,
        shape: InputShape,
        output: O,
        bound: &[BoundRow],
        peak_working_bytes: u64,
    ) -> Result<CertifiedRun<O>, GraphError> {
        let output_entries = output.entries();
        if output_entries > self.budget.max_output_entries {
            return Err(GraphError::BudgetExhausted {
                dimension: OUTPUT_ENTRIES,
                limit: self.budget.max_output_entries,
            });
        }
        let mut counters: BTreeMap<String, u64> = BTreeMap::new();
        for &(counter, _) in bound {
            if counter != OUTPUT_ENTRIES {
                counters.insert(counter.to_owned(), 0);
            }
        }
        for (&counter, &value) in &self.counters {
            if !counters.contains_key(counter) {
                return Err(GraphError::ComplexityBoundViolated {
                    counter,
                    observed: value,
                    bound: 0,
                });
            }
            counters.insert(counter.to_owned(), value);
        }
        for &(counter, limit) in bound {
            let observed = if counter == OUTPUT_ENTRIES {
                output_entries
            } else {
                counters.get(counter).copied().unwrap_or(0)
            };
            if observed > limit {
                return Err(GraphError::ComplexityBoundViolated {
                    counter,
                    observed,
                    bound: limit,
                });
            }
        }
        let mut encoder = CanonicalEncoder::new();
        encoder.text(identity.output_domain);
        output.encode(&mut encoder);
        if encoder.has_error() {
            return Err(GraphError::Inconsistent(
                "output exceeds the canonical encoding bounds".to_owned(),
            ));
        }
        let output_digest = ContentDigest::sha256(&encoder.finish());
        Ok(CertifiedRun {
            identity,
            node_count: shape.node_count,
            edge_count: shape.edge_count,
            input_digest: shape.input_digest,
            output,
            counters,
            operations: self.operations,
            output_entries,
            peak_working_bytes,
            decision_path_digest: ContentDigest::sha256(&self.path.finish()),
            output_digest,
        })
    }
}

/// Size and identity of the analysed input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputShape {
    /// Nodes.
    pub node_count: u64,
    /// Edges or arcs.
    pub edge_count: u64,
    /// Canonical input digest (projection plus every query parameter).
    pub input_digest: ContentDigest,
}

/// An answer that can be digested and sized.
pub trait CertifiedOutput {
    /// Emitted output entries (identities, values and certificate items).
    fn entries(&self) -> u64;
    /// Appends the canonical bytes of the whole answer (after the output domain).
    fn encode(&self, encoder: &mut CanonicalEncoder);
}

/// Encodes a list of identities with a length prefix.
pub fn encode_ids(encoder: &mut CanonicalEncoder, values: &[String]) {
    encoder.u64(values.len() as u64);
    for value in values {
        encoder.text(value);
    }
}

/// One complete, bound-checked run of a registered algorithm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertifiedRun<O> {
    /// Registered identity.
    pub identity: &'static AlgorithmIdentity,
    /// Nodes of the input.
    pub node_count: u64,
    /// Edges or arcs of the input.
    pub edge_count: u64,
    /// Canonical input digest.
    pub input_digest: ContentDigest,
    /// The answer.
    pub output: O,
    /// Observed dominant operation counts (every bounded counter, zero when unused).
    pub counters: BTreeMap<String, u64>,
    /// Operations charged against the budget.
    pub operations: u64,
    /// Output entries emitted.
    pub output_entries: u64,
    /// Deterministically accounted peak working bytes (the input is not counted).
    pub peak_working_bytes: u64,
    /// Digest of every tie-relevant decision in order.
    pub decision_path_digest: ContentDigest,
    /// Domain-separated digest of [`Self::output`].
    pub output_digest: ContentDigest,
}

impl<O> CertifiedRun<O> {
    /// The registered witness of this run over `projection_id` pinned at `anchor`.
    ///
    /// # Errors
    ///
    /// [`ContractError::InvalidIdentifier`] when `projection_id` is malformed.
    pub fn witness(
        &self,
        projection_id: &str,
        anchor: LedgerAnchor,
    ) -> Result<GraphAlgorithmWitness, ContractError> {
        GraphAlgorithmWitness::new(GraphAlgorithmWitnessParams {
            algorithm_id: self.identity.algorithm_id.to_owned(),
            implementation_id: self.identity.implementation_id.to_owned(),
            projection_id: projection_id.to_owned(),
            anchor,
            node_count: self.node_count,
            edge_count: self.edge_count,
            input_digest: self.input_digest,
            policy_id: self.identity.policy_id.to_owned(),
            dominant_operation_counts: self.counters.clone(),
            peak_working_bytes: self.peak_working_bytes,
            budget_consumed: BTreeMap::from([
                ("operations".to_owned(), self.operations),
                (OUTPUT_ENTRIES.to_owned(), self.output_entries),
            ]),
            exactness: self.identity.exactness.to_owned(),
            error_bound: None,
            stop_reason: GraphAlgorithmWitness::STOP_COMPLETED.to_owned(),
            decision_path_digest: self.decision_path_digest,
            output_digest: self.output_digest,
        })
    }
}

/// Re-checks a stored witness of `identity` against `bound` recomputed for its own size.
///
/// # Errors
///
/// [`GraphError::Inconsistent`] for a witness of another algorithm or implementation, or one
/// lacking a bounded counter; [`GraphError::ComplexityBoundViolated`] for a counter, unknown
/// counter, or output size above its bound.
pub fn check_witness(
    witness: &GraphAlgorithmWitness,
    identity: &AlgorithmIdentity,
    bound: &[BoundRow],
) -> Result<(), GraphError> {
    if witness.algorithm_id() != identity.algorithm_id
        || witness.implementation_id() != identity.implementation_id
        || witness.policy_id() != identity.policy_id
    {
        return Err(GraphError::Inconsistent(format!(
            "witness of {} ({}) is not {} ({})",
            witness.algorithm_id(),
            witness.implementation_id(),
            identity.algorithm_id,
            identity.implementation_id
        )));
    }
    let counts = witness.dominant_operation_counts();
    for (counter, &observed) in counts {
        if !bound.iter().any(|&(name, _)| name == counter) {
            return Err(GraphError::Inconsistent(format!(
                "witness carries unregistered counter {counter} = {observed}"
            )));
        }
    }
    for &(counter, limit) in bound {
        let observed = if counter == OUTPUT_ENTRIES {
            witness
                .budget_consumed()
                .get(OUTPUT_ENTRIES)
                .copied()
                .ok_or_else(|| {
                    GraphError::Inconsistent("witness lacks output entries".to_owned())
                })?
        } else {
            counts.get(counter).copied().ok_or_else(|| {
                GraphError::Inconsistent(format!("witness lacks counter {counter}"))
            })?
        };
        if observed > limit {
            return Err(GraphError::ComplexityBoundViolated {
                counter,
                observed,
                bound: limit,
            });
        }
    }
    Ok(())
}

/// `a * b` within `u64`, or the bound saturates (bounds only ever loosen on overflow).
#[must_use]
pub const fn mul(a: u64, b: u64) -> u64 {
    a.saturating_mul(b)
}

/// `a + b` within `u64`, saturating (bounds only).
#[must_use]
pub const fn add(a: u64, b: u64) -> u64 {
    a.saturating_add(b)
}

/// Checked addition of weights.
///
/// # Errors
///
/// [`GraphError::ArithmeticOverflow`] naming `quantity`.
pub fn checked_add(a: u64, b: u64, quantity: &'static str) -> Result<u64, GraphError> {
    a.checked_add(b)
        .ok_or(GraphError::ArithmeticOverflow(quantity))
}

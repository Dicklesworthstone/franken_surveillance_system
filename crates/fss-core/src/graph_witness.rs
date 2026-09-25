//! `GraphAlgorithmWitness` v1 (`schemas/graph_algorithm_witness.v1.json`, `SCHEMA-GRAPH-WITNESS-001`).
//!
//! Every planning-relevant graph execution (`GRAPH-INV-008`) emits one witness naming the
//! registered algorithm and implementation generation, the authorized immutable projection and its
//! canonical input digest, the authority anchor it was pinned to, the policy (directedness,
//! multiedge, weight, numeric and tie-break semantics), the observed dominant operation counts, the
//! accounted working bytes and budget use, the exactness class and error bound, the stop reason,
//! and the digests of the canonical decision path and output.
//!
//! The witness is derived cognition: it proves what was computed over which projection, never that
//! the projection is complete, and it grants no effect authority (`GRAPH-INV-004`). Its canonical
//! digest is domain-separated by [`GraphAlgorithmWitness::DIGEST_DOMAIN`]; field text is bounded
//! and validated against the registered schema grammar before a witness can be constructed.

use std::collections::BTreeMap;

use crate::{CanonicalEncode, CanonicalEncoder, ContentDigest, ContractError, LedgerAnchor};

/// Maximum entries in each count map of a witness.
pub const MAX_GRAPH_WITNESS_COUNTERS: usize = 32;
/// Maximum byte length of one count-map key.
pub const MAX_GRAPH_WITNESS_COUNTER_NAME_LEN: usize = 64;

/// One registered graph algorithm execution witness (`fss.graph_algorithm_witness.v1`).
#[derive(Clone, Debug, PartialEq)]
pub struct GraphAlgorithmWitness {
    algorithm_id: String,
    implementation_id: String,
    projection_id: String,
    anchor: LedgerAnchor,
    node_count: u64,
    edge_count: u64,
    input_digest: ContentDigest,
    policy_id: String,
    dominant_operation_counts: BTreeMap<String, u64>,
    peak_working_bytes: u64,
    budget_consumed: BTreeMap<String, u64>,
    exactness: String,
    error_bound: Option<f64>,
    stop_reason: String,
    decision_path_digest: ContentDigest,
    output_digest: ContentDigest,
}

/// Every field of a [`GraphAlgorithmWitness`], validated by [`GraphAlgorithmWitness::new`].
#[derive(Clone, Debug, PartialEq)]
pub struct GraphAlgorithmWitnessParams {
    /// Registered algorithm identity (`ALG-...`).
    pub algorithm_id: String,
    /// Implementation generation (`^[a-z0-9][a-z0-9:+._-]{7,255}$`).
    pub implementation_id: String,
    /// Authorized projection identity (1..=256 bytes).
    pub projection_id: String,
    /// Authority anchor the projection was compiled at.
    pub anchor: LedgerAnchor,
    /// Nodes of the projection.
    pub node_count: u64,
    /// Edges of the projection.
    pub edge_count: u64,
    /// Canonical digest of the immutable input projection.
    pub input_digest: ContentDigest,
    /// Policy identity: directedness, multiedge, weight, numeric, and tie-break semantics.
    pub policy_id: String,
    /// Observed algorithm-specific dominant operation counts.
    pub dominant_operation_counts: BTreeMap<String, u64>,
    /// Deterministically accounted peak working bytes.
    pub peak_working_bytes: u64,
    /// Budget dimensions consumed.
    pub budget_consumed: BTreeMap<String, u64>,
    /// Exactness class of this execution (for example `exact`).
    pub exactness: String,
    /// Error bound of an approximate execution; `None` for an exact one.
    pub error_bound: Option<f64>,
    /// Why the execution stopped (for example `completed`).
    pub stop_reason: String,
    /// Digest of the canonical decision path.
    pub decision_path_digest: ContentDigest,
    /// Digest of the canonical output.
    pub output_digest: ContentDigest,
}

fn is_algorithm_id(value: &str) -> bool {
    value.len() > 4
        && value.len() <= 256
        && value.starts_with("ALG-")
        && value[4..]
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
}

/// The schema's generation grammar `^[a-z0-9][a-z0-9:+._-]{7,255}$`.
fn is_generation_text(value: &str) -> bool {
    let bytes = value.as_bytes();
    (8..=256).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b":+._-".contains(byte)
        })
}

fn is_bounded_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn is_counter_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_GRAPH_WITNESS_COUNTER_NAME_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_counters(counters: &BTreeMap<String, u64>) -> bool {
    counters.len() <= MAX_GRAPH_WITNESS_COUNTERS && counters.keys().all(|key| is_counter_name(key))
}

fn encode_counters(encoder: &mut CanonicalEncoder, counters: &BTreeMap<String, u64>) {
    encoder.u64(counters.len() as u64);
    for (name, value) in counters {
        encoder.text(name);
        encoder.u64(*value);
    }
}

impl GraphAlgorithmWitness {
    /// Registered schema identity of the witness.
    pub const SCHEMA: &'static str = "fss.graph_algorithm_witness.v1";
    /// Canonical digest domain of the witness (`SCHEMA-DOMAIN-GRAPH-ALGORITHM-WITNESS-001`).
    pub const DIGEST_DOMAIN: &'static str = "fss.graph_algorithm_witness.receipt.v1";
    /// Stop reason of an execution that ran to completion.
    pub const STOP_COMPLETED: &'static str = "completed";
    /// Exactness class of an exact execution.
    pub const EXACT: &'static str = "exact";

    /// Validates every field against the registered schema grammar.
    ///
    /// # Errors
    ///
    /// [`ContractError::InvalidIdentifier`] for a malformed identifier, policy, exactness, stop
    /// reason or counter name, or an oversized counter map; [`ContractError::InvalidDigest`] for a
    /// non-finite or negative error bound.
    pub fn new(params: GraphAlgorithmWitnessParams) -> Result<Self, ContractError> {
        if !is_algorithm_id(&params.algorithm_id)
            || !is_generation_text(&params.implementation_id)
            || !is_bounded_text(&params.projection_id)
            || !is_bounded_text(&params.policy_id)
            || !is_bounded_text(&params.exactness)
            || !is_bounded_text(&params.stop_reason)
            || !valid_counters(&params.dominant_operation_counts)
            || !valid_counters(&params.budget_consumed)
        {
            return Err(ContractError::InvalidIdentifier);
        }
        if params
            .error_bound
            .is_some_and(|bound| !bound.is_finite() || bound < 0.0)
        {
            return Err(ContractError::InvalidDigest);
        }
        Ok(Self {
            algorithm_id: params.algorithm_id,
            implementation_id: params.implementation_id,
            projection_id: params.projection_id,
            anchor: params.anchor,
            node_count: params.node_count,
            edge_count: params.edge_count,
            input_digest: params.input_digest,
            policy_id: params.policy_id,
            dominant_operation_counts: params.dominant_operation_counts,
            peak_working_bytes: params.peak_working_bytes,
            budget_consumed: params.budget_consumed,
            exactness: params.exactness,
            error_bound: params.error_bound,
            stop_reason: params.stop_reason,
            decision_path_digest: params.decision_path_digest,
            output_digest: params.output_digest,
        })
    }

    /// Registered algorithm identity.
    #[must_use]
    pub fn algorithm_id(&self) -> &str {
        &self.algorithm_id
    }

    /// Implementation generation.
    #[must_use]
    pub fn implementation_id(&self) -> &str {
        &self.implementation_id
    }

    /// Authorized projection identity.
    #[must_use]
    pub fn projection_id(&self) -> &str {
        &self.projection_id
    }

    /// Authority anchor.
    #[must_use]
    pub fn anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }

    /// Nodes of the projection.
    #[must_use]
    pub fn node_count(&self) -> u64 {
        self.node_count
    }

    /// Edges of the projection.
    #[must_use]
    pub fn edge_count(&self) -> u64 {
        self.edge_count
    }

    /// Canonical input projection digest.
    #[must_use]
    pub fn input_digest(&self) -> ContentDigest {
        self.input_digest
    }

    /// Policy identity.
    #[must_use]
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    /// Observed dominant operation counts.
    #[must_use]
    pub fn dominant_operation_counts(&self) -> &BTreeMap<String, u64> {
        &self.dominant_operation_counts
    }

    /// Accounted peak working bytes.
    #[must_use]
    pub fn peak_working_bytes(&self) -> u64 {
        self.peak_working_bytes
    }

    /// Budget consumed.
    #[must_use]
    pub fn budget_consumed(&self) -> &BTreeMap<String, u64> {
        &self.budget_consumed
    }

    /// Exactness class.
    #[must_use]
    pub fn exactness(&self) -> &str {
        &self.exactness
    }

    /// Error bound (`None` for an exact execution).
    #[must_use]
    pub fn error_bound(&self) -> Option<f64> {
        self.error_bound
    }

    /// Stop reason.
    #[must_use]
    pub fn stop_reason(&self) -> &str {
        &self.stop_reason
    }

    /// Decision-path digest.
    #[must_use]
    pub fn decision_path_digest(&self) -> ContentDigest {
        self.decision_path_digest
    }

    /// Output digest.
    #[must_use]
    pub fn output_digest(&self) -> ContentDigest {
        self.output_digest
    }

    /// Canonical digest of the whole witness under [`Self::DIGEST_DOMAIN`].
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        ContentDigest::sha256(&encoder.finish())
    }
}

impl CanonicalEncode for GraphAlgorithmWitness {
    fn encode_canonical(&self, encoder: &mut CanonicalEncoder) {
        encoder.text(Self::DIGEST_DOMAIN);
        encoder.text(&self.algorithm_id);
        encoder.text(&self.implementation_id);
        encoder.text(&self.projection_id);
        self.anchor.encode_canonical(encoder);
        encoder.u64(self.node_count);
        encoder.u64(self.edge_count);
        encoder.digest(self.input_digest);
        encoder.text(&self.policy_id);
        encode_counters(encoder, &self.dominant_operation_counts);
        encoder.u64(self.peak_working_bytes);
        encode_counters(encoder, &self.budget_consumed);
        encoder.text(&self.exactness);
        match self.error_bound {
            None => encoder.tag(0),
            Some(bound) => {
                encoder.tag(1);
                encoder.u64(bound.to_bits());
            }
        }
        encoder.text(&self.stop_reason);
        encoder.digest(self.decision_path_digest);
        encoder.digest(self.output_digest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> GraphAlgorithmWitnessParams {
        GraphAlgorithmWitnessParams {
            algorithm_id: "ALG-BRIDGE-001".to_owned(),
            implementation_id: "fss-graph-algorithms:alg-bridge-001:v1".to_owned(),
            projection_id: "SensorCoverageGraph@commit:3".to_owned(),
            anchor: LedgerAnchor::genesis("site:test"),
            node_count: 4,
            edge_count: 3,
            input_digest: ContentDigest::sha256(b"input"),
            policy_id: "graph-policy:test".to_owned(),
            dominant_operation_counts: BTreeMap::from([("dfs_node_visits".to_owned(), 4)]),
            peak_working_bytes: 128,
            budget_consumed: BTreeMap::from([("operations".to_owned(), 10)]),
            exactness: GraphAlgorithmWitness::EXACT.to_owned(),
            error_bound: None,
            stop_reason: GraphAlgorithmWitness::STOP_COMPLETED.to_owned(),
            decision_path_digest: ContentDigest::sha256(b"path"),
            output_digest: ContentDigest::sha256(b"output"),
        }
    }

    #[test]
    fn valid_witness_round_trips_accessors_and_digest_is_field_sensitive()
    -> Result<(), ContractError> {
        let witness = GraphAlgorithmWitness::new(params())?;
        assert_eq!(witness.algorithm_id(), "ALG-BRIDGE-001");
        assert_eq!(witness.node_count(), 4);
        assert_eq!(
            witness.digest(),
            GraphAlgorithmWitness::new(params())?.digest()
        );
        let mut changed = params();
        changed.output_digest = ContentDigest::sha256(b"other");
        assert_ne!(
            witness.digest(),
            GraphAlgorithmWitness::new(changed)?.digest()
        );
        let mut counted = params();
        counted
            .dominant_operation_counts
            .insert("low_link_updates".to_owned(), 0);
        assert_ne!(
            witness.digest(),
            GraphAlgorithmWitness::new(counted)?.digest()
        );
        Ok(())
    }

    #[test]
    fn malformed_fields_are_refused() {
        type Mutation = Box<dyn Fn(&mut GraphAlgorithmWitnessParams)>;
        let cases: Vec<Mutation> = vec![
            Box::new(|p| p.algorithm_id = "alg-bridge-001".to_owned()),
            Box::new(|p| p.algorithm_id = "ALG-".to_owned()),
            Box::new(|p| p.implementation_id = "short".to_owned()),
            Box::new(|p| p.implementation_id = "Upper:case:impl".to_owned()),
            Box::new(|p| p.projection_id = String::new()),
            Box::new(|p| p.projection_id = "x".repeat(257)),
            Box::new(|p| p.policy_id = "line\nbreak".to_owned()),
            Box::new(|p| p.exactness = String::new()),
            Box::new(|p| p.stop_reason = String::new()),
            Box::new(|p| {
                p.dominant_operation_counts.insert("Bad-Name".to_owned(), 1);
            }),
            Box::new(|p| p.error_bound = Some(f64::NAN)),
            Box::new(|p| p.error_bound = Some(-1.0)),
        ];
        for mutate in cases {
            let mut candidate = params();
            mutate(&mut candidate);
            assert!(GraphAlgorithmWitness::new(candidate).is_err());
        }
    }
}

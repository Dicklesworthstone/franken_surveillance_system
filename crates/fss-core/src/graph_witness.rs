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
use std::error::Error;
use std::fmt;

use crate::decision_card_v1::{DecisionCardError, EvidenceAnchorRecordV1};
use crate::digest::Sha256Hasher;
use crate::json_input::{self, Value};
use crate::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest,
    ContractError, LedgerAnchor,
};

/// Maximum entries in each count map of a witness.
pub const MAX_GRAPH_WITNESS_COUNTERS: usize = 32;
/// Maximum byte length of one count-map key.
pub const MAX_GRAPH_WITNESS_COUNTER_NAME_LEN: usize = 64;
/// Magic 8-byte header for canonical `GraphAlgorithmWitness` binary wire envelopes.
pub const GRAPH_WITNESS_WIRE_MAGIC: [u8; 8] = *b"FSSGWT01";
/// Current format version for `GraphAlgorithmWitness` binary wire envelopes.
pub const GRAPH_WITNESS_FORMAT_VERSION: u32 = 1;
/// Hard upper bound on serialized `GraphAlgorithmWitness` binary wire bytes (64 KiB).
pub const MAX_GRAPH_WITNESS_WIRE_BYTES: usize = 64 * 1024;
const GRAPH_WITNESS_WIRE_HEADER_BYTES: usize = 16;
const GRAPH_WITNESS_WIRE_CHECKSUM_BYTES: usize = 32;

/// Typed codec and compatibility errors for `SCHEMA-GRAPH-WITNESS-001`
/// (`fss.graph_algorithm_witness.v1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GraphWitnessCodecError {
    /// Underlying contract validation failure.
    Contract(ContractError),
    /// Schema identity in JSON did not match the expected schema URI.
    SchemaMismatch {
        /// Expected schema identity.
        expected: &'static str,
        /// Observed schema identity.
        observed: String,
    },
    /// Wire envelope magic header did not match [`GRAPH_WITNESS_WIRE_MAGIC`].
    InvalidMagic,
    /// Wire envelope carried an unsupported format version.
    UnsupportedVersion {
        /// Unsupported version tag observed on the wire.
        version: u32,
    },
    /// Trailing SHA-256 checksum verification failed.
    ChecksumMismatch,
    /// Encoded or offered wire payload exceeded [`MAX_GRAPH_WITNESS_WIRE_BYTES`].
    WireTooLarge {
        /// Observed wire length in bytes.
        observed: usize,
        /// Configured hard maximum in bytes.
        maximum: usize,
    },
    /// Structural JSON or binary envelope error.
    MalformedPayload(String),
    /// Compatibility rule violated (algorithm, projection, policy, or output digest drift).
    CompatibilityViolation(String),
}

impl GraphWitnessCodecError {
    /// Stable error identity aligned with `registries/ERRORS.md`.
    #[must_use]
    pub const fn error_id(&self) -> &'static str {
        match self {
            Self::Contract(_) => "ERR-GRAPH-WITNESS-CONTRACT-001",
            Self::SchemaMismatch { .. }
            | Self::InvalidMagic
            | Self::UnsupportedVersion { .. }
            | Self::WireTooLarge { .. } => "ERR-SCHEMA-UNSUPPORTED-001",
            Self::ChecksumMismatch => "ERR-NEG-CHECKSUM-MISMATCH-001",
            Self::MalformedPayload(_) => "ERR-GRAPH-WITNESS-MALFORMED-001",
            Self::CompatibilityViolation(_) => "ERR-GRAPH-WITNESS-COMPAT-001",
        }
    }
}

impl fmt::Display for GraphWitnessCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(err) => write!(f, "graph witness contract error: {err}"),
            Self::SchemaMismatch { expected, observed } => {
                write!(
                    f,
                    "graph witness schema mismatch: expected '{expected}', observed '{observed}'"
                )
            }
            Self::InvalidMagic => write!(f, "graph witness wire magic mismatch"),
            Self::UnsupportedVersion { version } => {
                write!(f, "unsupported graph witness wire version {version}")
            }
            Self::ChecksumMismatch => write!(f, "graph witness wire checksum mismatch"),
            Self::WireTooLarge { observed, maximum } => {
                write!(
                    f,
                    "graph witness wire length {observed} exceeds maximum {maximum}"
                )
            }
            Self::MalformedPayload(detail) => write!(f, "malformed graph witness: {detail}"),
            Self::CompatibilityViolation(detail) => {
                write!(f, "graph witness compatibility violation: {detail}")
            }
        }
    }
}

impl Error for GraphWitnessCodecError {}

impl From<ContractError> for GraphWitnessCodecError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

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
        let error_bound = params
            .error_bound
            .map(|bound| if bound == 0.0 { 0.0 } else { bound });
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
            error_bound,
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

    /// Derived graph witnesses never grant effect authority (`GRAPH-INV-004`).
    #[must_use]
    pub const fn grants_effect_authority(&self) -> bool {
        false
    }

    /// Enforces `SCHEMA-GRAPH-WITNESS-001` compatibility rule:
    /// algorithm, projection, policy identity, and output digest are preserved across
    /// replay or implementation migration of the same projection input.
    pub fn verify_preserves_identity(&self, baseline: &Self) -> Result<(), GraphWitnessCodecError> {
        if self.algorithm_id != baseline.algorithm_id {
            return Err(GraphWitnessCodecError::CompatibilityViolation(format!(
                "algorithm_id drifted from '{}' to '{}'",
                baseline.algorithm_id, self.algorithm_id
            )));
        }
        if self.projection_id != baseline.projection_id {
            return Err(GraphWitnessCodecError::CompatibilityViolation(format!(
                "projection_id drifted from '{}' to '{}'",
                baseline.projection_id, self.projection_id
            )));
        }
        if self.policy_id != baseline.policy_id {
            return Err(GraphWitnessCodecError::CompatibilityViolation(format!(
                "policy_id drifted from '{}' to '{}'",
                baseline.policy_id, self.policy_id
            )));
        }
        if self.output_digest != baseline.output_digest {
            return Err(GraphWitnessCodecError::CompatibilityViolation(format!(
                "output_digest drifted from '{}' to '{}'",
                baseline.output_digest.to_text(),
                self.output_digest.to_text()
            )));
        }
        Ok(())
    }

    /// Encodes this witness into its versioned, checksummed canonical binary wire envelope
    /// (`FSSGWT01` v1 + domain-separated trailing SHA-256).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, GraphWitnessCodecError> {
        let mut encoder = CanonicalEncoder::new();
        self.encode_canonical(&mut encoder);
        let payload = encoder.finish_checked()?;
        let total_len = GRAPH_WITNESS_WIRE_HEADER_BYTES
            .checked_add(payload.len())
            .and_then(|n| n.checked_add(GRAPH_WITNESS_WIRE_CHECKSUM_BYTES))
            .ok_or(GraphWitnessCodecError::WireTooLarge {
                observed: usize::MAX,
                maximum: MAX_GRAPH_WITNESS_WIRE_BYTES,
            })?;
        if total_len > MAX_GRAPH_WITNESS_WIRE_BYTES {
            return Err(GraphWitnessCodecError::WireTooLarge {
                observed: total_len,
                maximum: MAX_GRAPH_WITNESS_WIRE_BYTES,
            });
        }
        let payload_len_u32 =
            u32::try_from(payload.len()).map_err(|_| GraphWitnessCodecError::WireTooLarge {
                observed: total_len,
                maximum: MAX_GRAPH_WITNESS_WIRE_BYTES,
            })?;
        let mut out = Vec::with_capacity(total_len);
        out.extend_from_slice(&GRAPH_WITNESS_WIRE_MAGIC);
        out.extend_from_slice(&GRAPH_WITNESS_FORMAT_VERSION.to_be_bytes());
        out.extend_from_slice(&payload_len_u32.to_be_bytes());
        out.extend_from_slice(&payload);
        let mut hasher = Sha256Hasher::new();
        hasher.update(Self::DIGEST_DOMAIN.as_bytes());
        hasher.update(&out);
        let checksum = hasher.finalize()?;
        out.extend_from_slice(&checksum);
        Ok(out)
    }

    /// Strictly decodes a versioned, checksummed canonical binary wire envelope (`FSSGWT01` v1).
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, GraphWitnessCodecError> {
        let min_len = GRAPH_WITNESS_WIRE_HEADER_BYTES + GRAPH_WITNESS_WIRE_CHECKSUM_BYTES;
        if bytes.len() < min_len {
            return Err(GraphWitnessCodecError::MalformedPayload(format!(
                "wire envelope length {} below minimum {min_len}",
                bytes.len()
            )));
        }
        if bytes.len() > MAX_GRAPH_WITNESS_WIRE_BYTES {
            return Err(GraphWitnessCodecError::WireTooLarge {
                observed: bytes.len(),
                maximum: MAX_GRAPH_WITNESS_WIRE_BYTES,
            });
        }
        if bytes[..8] != GRAPH_WITNESS_WIRE_MAGIC {
            return Err(GraphWitnessCodecError::InvalidMagic);
        }
        let version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if version != GRAPH_WITNESS_FORMAT_VERSION {
            return Err(GraphWitnessCodecError::UnsupportedVersion { version });
        }
        let declared_len =
            u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
        let expected_total = GRAPH_WITNESS_WIRE_HEADER_BYTES
            .checked_add(declared_len)
            .and_then(|n| n.checked_add(GRAPH_WITNESS_WIRE_CHECKSUM_BYTES))
            .ok_or_else(|| {
                GraphWitnessCodecError::MalformedPayload(
                    "declared payload length overflow".to_owned(),
                )
            })?;
        if bytes.len() != expected_total {
            return Err(GraphWitnessCodecError::MalformedPayload(format!(
                "wire length {} disagrees with declared payload length {declared_len}",
                bytes.len()
            )));
        }
        let split_at = bytes.len() - GRAPH_WITNESS_WIRE_CHECKSUM_BYTES;
        let (body, trailer) = bytes.split_at(split_at);
        let mut hasher = Sha256Hasher::new();
        hasher.update(Self::DIGEST_DOMAIN.as_bytes());
        hasher.update(body);
        let computed = hasher.finalize()?;
        if computed.as_slice() != trailer {
            return Err(GraphWitnessCodecError::ChecksumMismatch);
        }
        let payload = &body[GRAPH_WITNESS_WIRE_HEADER_BYTES..];
        let mut decoder = CanonicalDecoder::new(payload);
        let witness = <Self as CanonicalDecode>::decode_canonical(&mut decoder)?;
        decoder.ensure_finished()?;
        Ok(witness)
    }

    /// Emits deterministic canonical JSON strictly conforming to
    /// `schemas/graph_algorithm_witness.v1.json` (sorted keys, finite normalized floats).
    pub fn to_canonical_json(
        &self,
        device_generation: &str,
        stream_generation: &str,
    ) -> Result<String, GraphWitnessCodecError> {
        let anchor_rec = EvidenceAnchorRecordV1::from_ledger_anchor(
            &self.anchor,
            device_generation,
            stream_generation,
        )
        .map_err(|e| GraphWitnessCodecError::MalformedPayload(e.to_string()))?;
        let mut out = String::with_capacity(1024);
        out.push('{');
        push_kv_str(&mut out, "algorithmId", &self.algorithm_id);
        out.push(',');
        push_key(&mut out, "anchor");
        anchor_rec.write_canonical_json(&mut out);
        out.push(',');
        push_key(&mut out, "budgetConsumed");
        write_counter_map(&mut out, &self.budget_consumed);
        out.push(',');
        push_kv_str(
            &mut out,
            "decisionPathDigest",
            &self.decision_path_digest.to_text(),
        );
        out.push(',');
        push_key(&mut out, "dominantOperationCounts");
        write_counter_map(&mut out, &self.dominant_operation_counts);
        out.push(',');
        push_key(&mut out, "edgeCount");
        out.push_str(&self.edge_count.to_string());
        out.push(',');
        push_key(&mut out, "errorBound");
        match self.error_bound {
            None => out.push_str("null"),
            Some(bound) => {
                let norm = if bound == 0.0 { 0.0 } else { bound };
                out.push_str(&norm.to_string());
            }
        }
        out.push(',');
        push_kv_str(&mut out, "exactness", &self.exactness);
        out.push(',');
        push_kv_str(&mut out, "implementationId", &self.implementation_id);
        out.push(',');
        push_kv_str(&mut out, "inputDigest", &self.input_digest.to_text());
        out.push(',');
        push_key(&mut out, "nodeCount");
        out.push_str(&self.node_count.to_string());
        out.push(',');
        push_kv_str(&mut out, "outputDigest", &self.output_digest.to_text());
        out.push(',');
        push_key(&mut out, "peakWorkingBytes");
        out.push_str(&self.peak_working_bytes.to_string());
        out.push(',');
        push_kv_str(&mut out, "policyId", &self.policy_id);
        out.push(',');
        push_kv_str(&mut out, "projectionId", &self.projection_id);
        out.push(',');
        push_kv_str(&mut out, "schema", Self::SCHEMA);
        out.push(',');
        push_kv_str(&mut out, "stopReason", &self.stop_reason);
        out.push('}');
        Ok(out)
    }

    /// Strictly parses and validates a JSON document against
    /// `schemas/graph_algorithm_witness.v1.json`, rejecting unknown properties,
    /// duplicate keys, schema mismatches, negative/non-finite bounds, and malformed fields.
    pub fn from_json(text: &str) -> Result<Self, GraphWitnessCodecError> {
        const ALLOWED: &[&str] = &[
            "schema",
            "algorithmId",
            "implementationId",
            "projectionId",
            "anchor",
            "nodeCount",
            "edgeCount",
            "inputDigest",
            "policyId",
            "dominantOperationCounts",
            "peakWorkingBytes",
            "budgetConsumed",
            "exactness",
            "errorBound",
            "stopReason",
            "decisionPathDigest",
            "outputDigest",
        ];
        let val = json_input::parse(text)
            .map_err(|e| GraphWitnessCodecError::MalformedPayload(e.to_string()))?;
        let obj = val.object().ok_or_else(|| {
            GraphWitnessCodecError::MalformedPayload("root must be a JSON object".to_owned())
        })?;
        for k in obj.keys() {
            if !ALLOWED.contains(&k.as_str()) {
                return Err(GraphWitnessCodecError::MalformedPayload(format!(
                    "unknown property '{k}' in graph_algorithm_witness (additionalProperties: false)"
                )));
            }
        }
        let schema = req_str(obj, "schema")?;
        if schema != Self::SCHEMA {
            return Err(GraphWitnessCodecError::SchemaMismatch {
                expected: Self::SCHEMA,
                observed: schema.to_owned(),
            });
        }
        let algorithm_id = req_str(obj, "algorithmId")?.to_owned();
        let implementation_id = req_str(obj, "implementationId")?.to_owned();
        let projection_id = req_str(obj, "projectionId")?.to_owned();
        let anchor_val = obj
            .get("anchor")
            .ok_or_else(|| GraphWitnessCodecError::MalformedPayload("missing anchor".to_owned()))?;
        let anchor_rec =
            EvidenceAnchorRecordV1::from_json_value(anchor_val).map_err(|e| match e {
                DecisionCardError::SchemaMismatch { expected, observed } => {
                    GraphWitnessCodecError::SchemaMismatch { expected, observed }
                }
                other => GraphWitnessCodecError::MalformedPayload(other.to_string()),
            })?;
        let state_root = ContentDigest::parse(&anchor_rec.authority_root)?;
        let anchor = LedgerAnchor {
            site_lineage: anchor_rec.deployment_id,
            ledger_epoch: anchor_rec.observation_epoch,
            commit_sequence: anchor_rec.capsule_sequence,
            adapter_registry_epoch: anchor_rec.adapter_epoch,
            schema_epoch: anchor_rec.schema_epoch,
            policy_epoch: anchor_rec.policy_epoch,
            privacy_epoch: anchor_rec.privacy_epoch.unwrap_or(1),
            state_root,
        };
        let node_count = req_u64(obj, "nodeCount")?;
        let edge_count = req_u64(obj, "edgeCount")?;
        let input_digest = ContentDigest::parse(req_str(obj, "inputDigest")?)?;
        let policy_id = req_str(obj, "policyId")?.to_owned();
        let dominant_operation_counts = req_counter_map(obj, "dominantOperationCounts")?;
        let peak_working_bytes = req_u64(obj, "peakWorkingBytes")?;
        let budget_consumed = req_counter_map(obj, "budgetConsumed")?;
        let exactness = req_str(obj, "exactness")?.to_owned();
        let error_bound = match obj.get("errorBound").ok_or_else(|| {
            GraphWitnessCodecError::MalformedPayload("missing errorBound".to_owned())
        })? {
            Value::Null => None,
            Value::Number(raw) => {
                let parsed = raw.parse::<f64>().map_err(|_| {
                    GraphWitnessCodecError::MalformedPayload(
                        "errorBound must be a finite number or null".to_owned(),
                    )
                })?;
                if !parsed.is_finite() || parsed < 0.0 {
                    return Err(GraphWitnessCodecError::Contract(
                        ContractError::InvalidDigest,
                    ));
                }
                Some(if parsed == 0.0 { 0.0 } else { parsed })
            }
            _ => {
                return Err(GraphWitnessCodecError::MalformedPayload(
                    "errorBound must be a number or null".to_owned(),
                ));
            }
        };
        let stop_reason = req_str(obj, "stopReason")?.to_owned();
        let decision_path_digest = ContentDigest::parse(req_str(obj, "decisionPathDigest")?)?;
        let output_digest = ContentDigest::parse(req_str(obj, "outputDigest")?)?;

        Ok(Self::new(GraphAlgorithmWitnessParams {
            algorithm_id,
            implementation_id,
            projection_id,
            anchor,
            node_count,
            edge_count,
            input_digest,
            policy_id,
            dominant_operation_counts,
            peak_working_bytes,
            budget_consumed,
            exactness,
            error_bound,
            stop_reason,
            decision_path_digest,
            output_digest,
        })?)
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
                let norm = if bound == 0.0 { 0.0 } else { bound };
                encoder.tag(1);
                encoder.u64(norm.to_bits());
            }
        }
        encoder.text(&self.stop_reason);
        encoder.digest(self.decision_path_digest);
        encoder.digest(self.output_digest);
    }
}

fn decode_counters(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<BTreeMap<String, u64>, ContractError> {
    let raw_count = decoder.u64()?;
    let count = usize::try_from(raw_count).map_err(|_| ContractError::CountBoundExceeded)?;
    if count > MAX_GRAPH_WITNESS_COUNTERS || count.saturating_mul(16) > decoder.remaining() {
        return Err(ContractError::CountBoundExceeded);
    }
    let mut map = BTreeMap::new();
    for _ in 0..count {
        let name = decoder.text()?;
        if !is_counter_name(name) {
            return Err(ContractError::InvalidIdentifier);
        }
        if map
            .keys()
            .next_back()
            .is_some_and(|prev: &String| prev.as_str() >= name)
        {
            return Err(ContractError::NonCanonicalOrdering);
        }
        let value = decoder.u64()?;
        map.insert(name.to_owned(), value);
    }
    Ok(map)
}

impl CanonicalDecode for GraphAlgorithmWitness {
    fn decode_canonical(decoder: &mut CanonicalDecoder<'_>) -> Result<Self, ContractError> {
        let domain = decoder.text()?;
        if domain != Self::DIGEST_DOMAIN {
            return Err(ContractError::InvalidIdentifier);
        }
        let algorithm_id = decoder.text()?.to_owned();
        let implementation_id = decoder.text()?.to_owned();
        let projection_id = decoder.text()?.to_owned();
        let anchor = LedgerAnchor::decode_canonical(decoder)?;
        let node_count = decoder.u64()?;
        let edge_count = decoder.u64()?;
        let input_digest = decoder.digest()?;
        let policy_id = decoder.text()?.to_owned();
        let dominant_operation_counts = decode_counters(decoder)?;
        let peak_working_bytes = decoder.u64()?;
        let budget_consumed = decode_counters(decoder)?;
        let exactness = decoder.text()?.to_owned();
        let error_bound = match decoder.u8()? {
            0 => None,
            1 => {
                let bits = decoder.u64()?;
                let val = f64::from_bits(bits);
                if !val.is_finite() || val < 0.0 || (val == 0.0 && bits != 0.0_f64.to_bits()) {
                    return Err(ContractError::InvalidDigest);
                }
                Some(val)
            }
            tag => return Err(ContractError::UnknownEntryTag(tag)),
        };
        let stop_reason = decoder.text()?.to_owned();
        let decision_path_digest = decoder.digest()?;
        let output_digest = decoder.digest()?;
        Self::new(GraphAlgorithmWitnessParams {
            algorithm_id,
            implementation_id,
            projection_id,
            anchor,
            node_count,
            edge_count,
            input_digest,
            policy_id,
            dominant_operation_counts,
            peak_working_bytes,
            budget_consumed,
            exactness,
            error_bound,
            stop_reason,
            decision_path_digest,
            output_digest,
        })
    }
}

fn push_escaped_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn push_key(out: &mut String, key: &str) {
    push_escaped_str(out, key);
    out.push(':');
}

fn push_kv_str(out: &mut String, key: &str, val: &str) {
    push_key(out, key);
    push_escaped_str(out, val);
}

fn write_counter_map(out: &mut String, map: &BTreeMap<String, u64>) {
    out.push('{');
    for (idx, (k, v)) in map.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        push_key(out, k);
        out.push_str(&v.to_string());
    }
    out.push('}');
}

fn req_str<'a>(
    obj: &'a BTreeMap<String, Value>,
    key: &str,
) -> Result<&'a str, GraphWitnessCodecError> {
    obj.get(key)
        .ok_or_else(|| GraphWitnessCodecError::MalformedPayload(format!("missing {key}")))?
        .text()
        .ok_or_else(|| GraphWitnessCodecError::MalformedPayload(format!("{key} must be string")))
}

fn req_u64(obj: &BTreeMap<String, Value>, key: &str) -> Result<u64, GraphWitnessCodecError> {
    match obj
        .get(key)
        .ok_or_else(|| GraphWitnessCodecError::MalformedPayload(format!("missing {key}")))?
    {
        Value::Number(raw) => raw
            .parse::<u64>()
            .map_err(|_| GraphWitnessCodecError::MalformedPayload(format!("{key} must be u64"))),
        _ => Err(GraphWitnessCodecError::MalformedPayload(format!(
            "{key} must be integer"
        ))),
    }
}

fn req_counter_map(
    obj: &BTreeMap<String, Value>,
    key: &str,
) -> Result<BTreeMap<String, u64>, GraphWitnessCodecError> {
    let map = obj
        .get(key)
        .ok_or_else(|| GraphWitnessCodecError::MalformedPayload(format!("missing {key}")))?
        .object()
        .ok_or_else(|| {
            GraphWitnessCodecError::MalformedPayload(format!("{key} must be JSON object"))
        })?;
    if map.len() > MAX_GRAPH_WITNESS_COUNTERS {
        return Err(GraphWitnessCodecError::Contract(
            ContractError::CountBoundExceeded,
        ));
    }
    let mut out = BTreeMap::new();
    for (k, v) in map {
        if !is_counter_name(k) {
            return Err(GraphWitnessCodecError::Contract(
                ContractError::InvalidIdentifier,
            ));
        }
        let n = match v {
            Value::Number(raw) => raw.parse::<u64>().map_err(|_| {
                GraphWitnessCodecError::MalformedPayload(format!("{key}.{k} must be u64"))
            })?,
            _ => {
                return Err(GraphWitnessCodecError::MalformedPayload(format!(
                    "{key}.{k} must be integer"
                )));
            }
        };
        out.insert(k.clone(), n);
    }
    Ok(out)
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

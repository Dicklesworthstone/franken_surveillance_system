#![forbid(unsafe_code)]
//! Pure-Rust model invocation/receipt protocol (FSS-072).
//!
//! The protocol binds every model result to EXACT identities: the model
//! package root (manifest digest), the IR graph (canonical digest +
//! generation), the named input tensors (canonical digests + generations),
//! and the preprocess/calibration generations. Evaluation is deterministic
//! and replayable; identical specs yield identical receipts.
//!
//! ## Reference evaluation mode: `DigestBinding`
//!
//! The deterministic reference evaluates the validated IR graph in
//! topological order, deriving each node output as a content digest over
//! `H(op ‖ sorted input digests ‖ canonical attributes)`. This produces
//! real, independently verifiable provenance commitments — "this exact
//! graph applied to these exact inputs yields this output identity" —
//! WITHOUT claiming numeric execution: arithmetic kernel semantics arrive
//! with the WP-080 kernel beads, and the receipt's mode field keeps the
//! claim honest. Numeric modes will join this protocol as kernels land;
//! they cannot upgrade a digest-binding receipt silently.
//!
//! Typed outcomes (per the contract): `Completed`, `Failed`, `Quarantined`
//! (validator refusal), `Abstained` (no reference kernel binding for an
//! op — named per node), and `StaleGeneration` refusals at prepare time.

use std::collections::BTreeMap;

use fss_core::{ContentDigest, Generation};

use crate::canonical::compute_model_ir_digest;
use crate::graph::ModelIrGraph;
use crate::node::GraphNode;

/// Hard bound on nodes executed in one invocation.
pub const MAX_INVOCATION_NODES: usize = 100_000;
/// Hard bound on named inputs.
pub const MAX_INVOCATION_INPUTS: usize = 256;

/// One named input binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputBinding {
    /// Tensor name (must match a graph input port).
    pub name: String,
    /// Canonical tensor digest.
    pub digest: ContentDigest,
    /// Tensor generation (must equal the graph input port's generation).
    pub generation: Generation,
    /// Caller-declared tensor byte size, when known. The receipt sums ONLY
    /// declared sizes; it never invents byte costs for digest-only
    /// bindings (None propagates to the receipt).
    pub declared_bytes: Option<u64>,
}

/// An immutable invocation request. The digest of its canonical form is
/// the idempotency key: the same spec always yields the same receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelInvocationSpec {
    /// Immutable model package root (manifest v1 digest).
    pub model_root: ContentDigest,
    /// Preprocess pipeline generation.
    pub preprocess_generation: Generation,
    /// Calibration table generation, when the model is calibrated.
    pub calibration_generation: Option<Generation>,
    /// Named input bindings.
    pub inputs: Vec<InputBinding>,
    /// Execution budget: maximum nodes the invocation may traverse.
    pub max_nodes: usize,
}

impl ModelInvocationSpec {
    /// Canonical digest of this spec (the invocation identity).
    ///
    /// # Errors
    /// Returns a typed error if the canonical encoding fails.
    pub fn digest(&self) -> Result<ContentDigest, InvocationError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.model_root.bytes());
        bytes.extend_from_slice(&self.preprocess_generation.get().to_be_bytes());
        match self.calibration_generation {
            // Full 64-bit encoding: the idempotency key must be injective
            // in every generation value (a truncated encoding would let
            // distinct specs collide).
            Some(cal) => {
                bytes.push(1);
                bytes.extend_from_slice(&cal.get().to_be_bytes());
            }
            None => bytes.push(0),
        }
        for input in &self.inputs {
            bytes.extend_from_slice(input.name.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(&input.digest.bytes());
            bytes.extend_from_slice(&input.generation.get().to_be_bytes());
        }
        bytes.extend_from_slice(&(self.max_nodes as u64).to_be_bytes());
        Ok(ContentDigest::sha256(&bytes))
    }
}

/// Terminal outcome of an invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvocationOutcome {
    /// Evaluation completed; outputs are digest-bound.
    Completed {
        /// Named output digests, in graph output order.
        outputs: Vec<(String, ContentDigest)>,
        /// Nodes evaluated.
        nodes_evaluated: usize,
        /// Sum of caller-declared input sizes; None when any binding is
        /// digest-only (never an invented figure).
        declared_input_bytes: Option<u64>,
    },
    /// A named node had no reference binding (typed abstention, never a
    /// silent skip).
    Abstained {
        /// The node that abstained.
        node_id: String,
        /// The op lacking a reference kernel binding.
        op: String,
        /// Nodes evaluated before abstention.
        nodes_evaluated: usize,
    },
    /// The graph refused validation (quarantine, not execution).
    Quarantined {
        /// Machine-readable validator refusal.
        reason: String,
    },
}

impl ModelReceipt {
    /// Whether this outcome counts against an invocation-count quota
    /// (completed outcomes only; abstained and quarantined work did not
    /// run and must not consume budget).
    #[must_use]
    pub fn outcome_is_counted(&self) -> bool {
        matches!(self.outcome, InvocationOutcome::Completed { .. })
    }
}

/// The invocation receipt: durable proof of what was bound and produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelReceipt {
    /// Spec digest (idempotency key).
    pub invocation: ContentDigest,
    /// Canonical IR digest actually evaluated.
    pub ir_digest: ContentDigest,
    /// IR generation.
    pub ir_generation: Generation,
    /// Evaluation mode (reference: digest binding).
    pub mode: &'static str,
    /// Terminal outcome.
    pub outcome: InvocationOutcome,
}

/// Typed protocol refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvocationError {
    /// An input name is not a graph input port, or a port is unbound.
    InputBinding {
        /// The offending name.
        name: String,
    },
    /// An input generation differs from the graph port's generation.
    StaleGeneration {
        /// The offending input name.
        name: String,
        /// Bound generation.
        bound: Generation,
        /// Required generation.
        required: Generation,
    },
    /// The node budget was exhausted.
    BudgetExhausted {
        /// The bound maximum.
        max_nodes: usize,
    },
    /// Too many inputs.
    TooManyInputs {
        /// The count supplied.
        count: usize,
    },
    /// Digest computation failed.
    Digest(String),
    /// Admission control refused the invocation (quota or memory
    /// pressure), with the exact cause.
    Quota(crate::quotas::QuotaError),
}

impl std::fmt::Display for InvocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InputBinding { name } => write!(f, "unbound or unknown input '{name}'"),
            Self::StaleGeneration {
                name,
                bound,
                required,
            } => write!(
                f,
                "stale generation on '{name}': bound {}, required {required}",
                bound.get()
            ),
            Self::BudgetExhausted { max_nodes } => {
                write!(f, "node budget exhausted (max {max_nodes})")
            }
            Self::TooManyInputs { count } => {
                write!(f, "too many inputs ({count} > {MAX_INVOCATION_INPUTS})")
            }
            Self::Digest(detail) => write!(f, "digest failure: {detail}"),
            Self::Quota(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for InvocationError {}

impl InvocationError {
    /// Whether this refusal carries an embedded quota/pressure cause.
    #[must_use]
    pub fn quota_cause(&self) -> Option<&crate::quotas::QuotaError> {
        match self {
            Self::Quota(e) => Some(e),
            _ => None,
        }
    }
}

/// A validated, generation-bound invocation ready to evaluate.
#[derive(Clone, Debug)]
pub struct PreparedInvocation {
    spec: ModelInvocationSpec,
    ir_digest: ContentDigest,
    ir_generation: Generation,
}

impl PreparedInvocation {
    /// The canonical IR digest bound at prepare time.
    #[must_use]
    pub fn ir_digest(&self) -> ContentDigest {
        self.ir_digest
    }

    /// The invocation spec bound at prepare time.
    #[must_use]
    pub fn spec(&self) -> &ModelInvocationSpec {
        &self.spec
    }
}

/// Prepares an invocation: validates the graph (quarantine on refusal),
/// checks every input binding by name and generation, and pins the
/// canonical IR digest. Preparation performs no evaluation.
///
/// # Errors
/// Typed refusals for unbound inputs, stale generations, and limits.
pub fn prepare(
    graph: &ModelIrGraph,
    spec: &ModelInvocationSpec,
) -> Result<PreparedInvocation, InvocationError> {
    if spec.inputs.len() > MAX_INVOCATION_INPUTS {
        return Err(InvocationError::TooManyInputs {
            count: spec.inputs.len(),
        });
    }
    if graph.validate().is_err() {
        // Quarantine is a PREPARE-time terminal fact: surface it as a
        // completed preparation whose evaluation quarantines. The canonical
        // encoder refuses invalid graphs, so quarantined preparations carry
        // a structural fallback digest identifying the attempted graph —
        // their receipts never claim canonical binding (the outcome says
        // Quarantined).
        let ir_digest = match compute_model_ir_digest(graph) {
            Ok(digest) => digest,
            Err(_) => ContentDigest::sha256(
                format!("quarantine:{}:gen:{}", graph.id(), graph.generation().get()).as_bytes(),
            ),
        };
        return Ok(PreparedInvocation {
            spec: spec.clone(),
            ir_digest,
            ir_generation: graph.generation(),
        });
    }
    let mut bound = BTreeMap::new();
    for input in &spec.inputs {
        bound.insert(input.name.clone(), input);
    }
    for port in graph.inputs() {
        match bound.get(port.name()) {
            None => {
                return Err(InvocationError::InputBinding {
                    name: port.name().to_string(),
                });
            }
            Some(binding) => {
                if binding.generation != port.generation() {
                    return Err(InvocationError::StaleGeneration {
                        name: port.name().to_string(),
                        bound: binding.generation,
                        required: port.generation(),
                    });
                }
            }
        }
    }
    for name in bound.keys() {
        if !graph.inputs().iter().any(|p| p.name() == name) {
            return Err(InvocationError::InputBinding { name: name.clone() });
        }
    }
    let ir_digest =
        compute_model_ir_digest(graph).map_err(|e| InvocationError::Digest(format!("{e}")))?;
    Ok(PreparedInvocation {
        spec: spec.clone(),
        ir_digest,
        ir_generation: graph.generation(),
    })
}

/// Evaluates a prepared invocation in the reference digest-binding mode.
///
/// Every node output is derived as `H(op ‖ input digests ‖ canonical
/// attrs)`; graph outputs bind to the producing nodes' digests. The
/// result is a pure function of `(graph, spec)`.
///
/// # Errors
/// Budget exhaustion is a typed refusal; validator and binding refusals
/// already happened at prepare.
pub fn execute(
    graph: &ModelIrGraph,
    prepared: &PreparedInvocation,
) -> Result<ModelReceipt, InvocationError> {
    execute_with_admission(graph, prepared, &KernelAdmission::admit_all())
}

/// [`execute`] with an explicit kernel-admission table.
///
/// # Errors
/// Same typed refusals as [`execute`].
pub fn execute_with_admission(
    graph: &ModelIrGraph,
    prepared: &PreparedInvocation,
    admission: &KernelAdmission,
) -> Result<ModelReceipt, InvocationError> {
    let invocation = prepared.spec.digest()?;
    // Re-validate: the receipt records quarantine honestly.
    if let Err(e) = graph.validate() {
        return Ok(ModelReceipt {
            invocation,
            ir_digest: prepared.ir_digest,
            ir_generation: prepared.ir_generation,
            mode: "digest-binding",
            outcome: InvocationOutcome::Quarantined {
                reason: format!("{e}"),
            },
        });
    }
    let mut values: BTreeMap<String, ContentDigest> = BTreeMap::new();
    let mut declared_total: Option<u64> = Some(0);
    for input in &prepared.spec.inputs {
        values.insert(input.name.clone(), input.digest);
        declared_total = match (declared_total, input.declared_bytes) {
            (Some(acc), Some(bytes)) => Some(acc.saturating_add(bytes)),
            _ => None,
        };
    }
    let mut nodes_evaluated = 0usize;
    let mut node_outputs: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for node in topological(graph) {
        if nodes_evaluated >= prepared.spec.max_nodes || nodes_evaluated >= MAX_INVOCATION_NODES {
            return Err(InvocationError::BudgetExhausted {
                max_nodes: prepared.spec.max_nodes,
            });
        }
        if !admission.binds(node) {
            return Ok(ModelReceipt {
                invocation,
                ir_digest: prepared.ir_digest,
                ir_generation: prepared.ir_generation,
                mode: "digest-binding",
                outcome: InvocationOutcome::Abstained {
                    node_id: node.id().to_string(),
                    op: node.op().stable_id().to_string(),
                    nodes_evaluated,
                },
            });
        };
        let mut material = Vec::new();
        material.extend_from_slice(node.id().as_bytes());
        material.push(0);
        material.extend_from_slice(node.op().stable_id().as_bytes());
        material.push(0);
        // Canonical attribute binding: BTreeMap iterates in sorted key
        // order, so the digest is representation-independent.
        let mut attr_material = Vec::new();
        for (key, value) in node.attributes().iter() {
            attr_material.extend_from_slice(key.as_bytes());
            attr_material.push(0);
            attr_material.extend_from_slice(&crate::canonical::encode_canonical_attr_value(value));
            material_attr_sep(&mut attr_material);
        }
        material.extend_from_slice(&attr_material);
        material.push(0);
        let mut input_digests = Vec::new();
        for in_name in node.inputs() {
            let digest = values
                .get(in_name)
                .ok_or_else(|| InvocationError::InputBinding {
                    name: in_name.clone(),
                })?;
            input_digests.push(*digest);
        }
        input_digests.sort();
        for digest in input_digests {
            material.extend_from_slice(&digest.bytes());
        }
        let output_digest = ContentDigest::sha256(&material);
        for out_name in node.outputs() {
            values.insert(out_name.clone(), output_digest);
            node_outputs
                .entry(node.id())
                .or_default()
                .push(out_name.clone());
        }
        nodes_evaluated += 1;
    }
    let mut outputs = Vec::new();
    for port in graph.outputs() {
        let digest = values
            .get(port.name())
            .ok_or_else(|| InvocationError::InputBinding {
                name: port.name().to_string(),
            })?;
        outputs.push((port.name().to_string(), *digest));
    }
    Ok(ModelReceipt {
        invocation,
        ir_digest: prepared.ir_digest,
        ir_generation: prepared.ir_generation,
        mode: "digest-binding",
        outcome: InvocationOutcome::Completed {
            outputs,
            nodes_evaluated,
            declared_input_bytes: declared_total,
        },
    })
}

fn material_attr_sep(out: &mut Vec<u8>) {
    out.push(0xFF);
}

/// Which ops the evaluation mode will bind. The default table admits every
/// validated op structurally; kernel beads narrow it as numeric modes
/// arrive. A test-local table can exclude ops to exercise [`InvocationOutcome::Abstained`].
#[derive(Clone, Debug, Default)]
pub struct KernelAdmission {
    excluded: std::collections::BTreeSet<&'static str>,
}

impl KernelAdmission {
    /// The default admission: every validated op binds in digest-binding
    /// mode.
    #[must_use]
    pub fn admit_all() -> Self {
        Self::default()
    }

    /// Excludes one op (by stable id) from binding; invocations reaching
    /// it abstain.
    #[must_use]
    pub fn exclude_op(mut self, stable_id: &'static str) -> Self {
        self.excluded.insert(stable_id);
        self
    }

    fn binds(&self, node: &GraphNode) -> bool {
        !self.excluded.contains(node.op().stable_id())
    }
}

/// Topological order over the graph's nodes (Kahn). The validator already
/// guarantees acyclicity; this is the evaluator's own ordering so the
/// receipt does not depend on stored node order.
fn topological(graph: &ModelIrGraph) -> Vec<&GraphNode> {
    let nodes = graph.nodes();
    let mut produced_by: BTreeMap<&str, &GraphNode> = BTreeMap::new();
    for node in nodes {
        for out in node.outputs() {
            produced_by.insert(out.as_str(), node);
        }
    }
    let mut indegree: BTreeMap<&str, usize> = BTreeMap::new();
    let mut dependents: BTreeMap<&str, Vec<&GraphNode>> = BTreeMap::new();
    for node in nodes {
        let mut deg = 0usize;
        for in_name in node.inputs() {
            if let Some(producer) = produced_by.get(in_name.as_str())
                && !std::ptr::eq(*producer, node)
            {
                deg += 1;
                dependents.entry(producer.id()).or_default().push(node);
            }
        }
        indegree.entry(node.id()).or_insert(deg);
    }
    let mut ready: Vec<&GraphNode> = nodes
        .iter()
        .filter(|n| indegree.get(n.id()).copied().unwrap_or(0) == 0)
        .collect();
    let mut ordered = Vec::with_capacity(nodes.len());
    while let Some(node) = ready.pop() {
        ordered.push(node);
        if let Some(deps) = dependents.get(node.id()) {
            for dep in deps {
                if let Some(deg) = indegree.get_mut(dep.id()) {
                    *deg -= 1;
                    if *deg == 0 {
                        ready.push(dep);
                    }
                }
            }
        }
    }
    ordered
}

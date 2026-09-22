#![forbid(unsafe_code)]
//! Deterministic liveness for materializing, out-of-place graph executors.
//!
//! Inputs stay resident for the whole invocation: removing a borrowed input from
//! an executor map does not free the caller's weights. Every node still executes,
//! including dead outputs. Outputs are allocated before last-use inputs retire.
//! This is a logical tensor-payload schedule, not an allocator/RSS certificate or
//! permission to alias buffers. Backend scratch must be reserved separately.

use std::collections::{BTreeMap, BTreeSet};
use fss_core::{CanonicalEncoder, ContentDigest};
use fss_tensor::{TensorError, MAX_STORAGE_BYTES};
use crate::{AttrValue, GraphValidator, ModelIrError, ModelIrGraph, ProducerId,
    TensorPort, infer_operator_outputs};

/// Versioned materializing liveness semantics; no graph/operator IDs are changed.
pub const MEMORY_PLAN_DOMAIN: &str = "fss.model_ir.materialized_liveness.v1";
/// Hard graph breadth ceiling before invoking the shared validator.
pub const MAX_MEMORY_PLAN_NODES: usize = 4096;
/// Hard count of graph inputs plus produced values.
pub const MAX_MEMORY_PLAN_VALUES: usize = 16_384;
/// Hard count of declared input/output references, including repeated uses.
pub const MAX_MEMORY_PLAN_REFERENCES: usize = 65_536;
/// Hard logical text/list metadata ceiling before validation or cloning.
pub const MAX_MEMORY_PLAN_METADATA_BYTES: usize = 4 * 1024 * 1024;

/// Caller-narrowable planning limits. Zero is valid for an empty category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryPlanLimits {
    /// Maximum computation nodes, at most MAX_MEMORY_PLAN_NODES.
    pub max_nodes: usize,
    /// Maximum inputs plus node outputs, at most MAX_MEMORY_PLAN_VALUES.
    pub max_values: usize,
    /// Maximum input/output references, at most MAX_MEMORY_PLAN_REFERENCES.
    pub max_references: usize,
    /// Maximum logical text and attribute payload, not allocator overhead.
    pub max_metadata_bytes: usize,
}
impl Default for MemoryPlanLimits {
    fn default() -> Self {
        Self { max_nodes: MAX_MEMORY_PLAN_NODES, max_values: MAX_MEMORY_PLAN_VALUES,
            max_references: MAX_MEMORY_PLAN_REFERENCES,
            max_metadata_bytes: MAX_MEMORY_PLAN_METADATA_BYTES }
    }
}

/// Planning refuses the entire graph; a partial release schedule never escapes.
#[derive(Clone, Debug, PartialEq)]
pub enum MemoryPlanError {
    /// Shared IR validation or inference refused the graph.
    Ir(ModelIrError),
    /// Tensor dimensions or byte arithmetic were invalid.
    Tensor(TensorError),
    /// A hard or caller-supplied planning bound was exceeded.
    Limit(&'static str),
    /// Caller requested cancellation at a planning checkpoint.
    Cancelled,
    /// Checked aggregate byte arithmetic overflowed.
    Overflow,
    /// The scratch schedule does not have exactly one entry per node.
    ScratchLength,
    /// Inferred topology and liveness did not agree.
    Inconsistent,
}
impl From<ModelIrError> for MemoryPlanError {
    fn from(e: ModelIrError) -> Self { Self::Ir(e) }
}
impl From<TensorError> for MemoryPlanError {
    fn from(e: TensorError) -> Self { Self::Tensor(e) }
}
impl std::fmt::Display for MemoryPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ir(_) => "memory plan graph refused",
            Self::Tensor(_) => "memory plan tensor refused",
            Self::Limit(_) => "memory plan bound exceeded",
            Self::Cancelled => "memory plan cancelled",
            Self::Overflow => "memory plan byte arithmetic overflow",
            Self::ScratchLength => "memory plan scratch schedule length mismatch",
            Self::Inconsistent => "memory plan topology mismatch",
        })
    }
}
impl std::error::Error for MemoryPlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ir(e) => Some(e), Self::Tensor(e) => Some(e),
            Self::Limit(_) | Self::Cancelled | Self::Overflow | Self::ScratchLength
            | Self::Inconsistent => None,
        }
    }
}

/// One inferred logical value. Produced values have distinct materialized storage.
#[derive(Clone, Debug, PartialEq)]
pub struct TensorLifetime {
    port: TensorPort,
    bytes: usize,
    producer: Option<usize>,
    release_after: Option<usize>,
}
impl TensorLifetime {
    /// Exact inferred dtype/shape/generation contract.
    pub fn port(&self) -> &TensorPort { &self.port }
    /// Contiguous logical payload bytes, not backing storage of a caller view.
    pub fn bytes(&self) -> usize { self.bytes }
    /// Zero-based producing step; None denotes caller-owned input.
    pub fn producer(&self) -> Option<usize> { self.producer }
    /// Release only AFTER this node completes. None pins an input or graph output.
    pub fn release_after(&self) -> Option<usize> { self.release_after }
}

/// A canonical execution boundary, including output-before-retirement overlap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryStep {
    node_id: String,
    produced: Vec<String>,
    release_after: Vec<String>,
    live_bytes: usize,
    retained_bytes: usize,
}
impl MemoryStep {
    /// Node in the shared validator's canonical topological order.
    pub fn node_id(&self) -> &str { &self.node_id }
    /// Outputs that must be materialized at this step, including unused values.
    pub fn produced(&self) -> &[String] { &self.produced }
    /// Sorted values that may be dropped after the output is complete.
    pub fn release_after(&self) -> &[String] { &self.release_after }
    /// Resident inputs and activations INCLUDING all new output payloads.
    pub fn live_bytes(&self) -> usize { self.live_bytes }
    /// Resident payload after last-use retirements, including pinned graph outputs.
    pub fn retained_bytes(&self) -> usize { self.retained_bytes }
}

/// Immutable exact-graph liveness schedule. No activation data is read or allocated.
#[derive(Clone, Debug, PartialEq)]
pub struct MemoryPlan {
    graph: ContentDigest,
    digest: ContentDigest,
    values: BTreeMap<String, TensorLifetime>,
    steps: Vec<MemoryStep>,
    input_bytes: usize,
    cumulative_bytes: usize,
    peak_live_bytes: usize,
    output_bytes: usize,
}
impl MemoryPlan {
    /// Plan a bounded graph using the existing validation and shape rules.
    pub fn compile(graph: &ModelIrGraph, limits: MemoryPlanLimits)
        -> Result<Self, MemoryPlanError> {
        Self::compile_cancellable(graph, limits, || false)
    }

    /// Plan with caller-owned cooperative cancellation. The callback is checked
    /// around validation, each node, lifetime collection and final sealing.
    /// The existing shared validator is bounded here but not internally interruptible.
    pub fn compile_cancellable(
        graph: &ModelIrGraph, limits: MemoryPlanLimits, mut cancelled: impl FnMut() -> bool,
    ) -> Result<Self, MemoryPlanError> {
        checkpoint(&mut cancelled)?;
        admit(graph, limits, &mut cancelled)?;
        GraphValidator::validate(graph)?;
        checkpoint(&mut cancelled)?;
        let mut producers = BTreeMap::new();
        for port in graph.inputs() { producers.insert(port.name(), ProducerId::GraphInput); }
        for node in graph.nodes() {
            for name in node.outputs() { producers.insert(name.as_str(), ProducerId::Node(node.id())); }
        }
        let order = GraphValidator::topological_sort(graph, &producers)?;
        let pinned: BTreeSet<&str> = graph.outputs().iter().map(TensorPort::name).collect();
        let mut last_use: BTreeMap<&str, usize> = BTreeMap::new();
        for (position, node) in order.iter().enumerate() {
            checkpoint(&mut cancelled)?;
            for name in node.outputs() { last_use.entry(name.as_str()).or_insert(position); }
            for name in node.inputs() { last_use.insert(name.as_str(), position); }
        }
        let mut values = BTreeMap::new();
        let mut input_bytes = 0;
        for port in graph.inputs() {
            let bytes = payload_bytes(port)?;
            input_bytes = add(input_bytes, bytes)?;
            values.insert(port.name().to_owned(), TensorLifetime {
                port: port.clone(), bytes, producer: None, release_after: None,
            });
        }
        let mut cumulative_bytes = input_bytes;
        for (position, node) in order.iter().enumerate() {
            checkpoint(&mut cancelled)?;
            let input_ports = node.inputs().iter().map(|name| {
                values.get(name).map(|v| &v.port).ok_or(MemoryPlanError::Inconsistent)
            }).collect::<Result<Vec<_>, _>>()?;
            let outputs = infer_operator_outputs(node.id(), node.op(), &input_ports,
                node.outputs(), node.attributes(), graph.generation())?;
            for port in outputs {
                let bytes = payload_bytes(&port)?;
                cumulative_bytes = add(cumulative_bytes, bytes)?;
                let release_after = if pinned.contains(port.name()) { None } else {
                    Some(*last_use.get(port.name()).ok_or(MemoryPlanError::Inconsistent)?)
                };
                values.insert(port.name().to_owned(), TensorLifetime {
                    port, bytes, producer: Some(position), release_after,
                });
            }
        }
        let mut releases = vec![Vec::new(); order.len()];
        for (name, value) in &values {
            checkpoint(&mut cancelled)?;
            if let Some(position) = value.release_after {
                releases.get_mut(position).ok_or(MemoryPlanError::Inconsistent)?.push(name.clone());
            }
        }
        let mut steps = Vec::new();
        steps.try_reserve_exact(order.len()).map_err(|_| MemoryPlanError::Limit("allocation"))?;
        let mut resident = input_bytes;
        let mut peak_live_bytes = input_bytes;
        for (position, node) in order.iter().enumerate() {
            checkpoint(&mut cancelled)?;
            for name in node.outputs() {
                resident = add(resident, values.get(name).ok_or(MemoryPlanError::Inconsistent)?.bytes)?;
            }
            let live_bytes = resident;
            peak_live_bytes = peak_live_bytes.max(resident);
            for name in &releases[position] {
                resident = resident.checked_sub(values.get(name)
                    .ok_or(MemoryPlanError::Inconsistent)?.bytes).ok_or(MemoryPlanError::Inconsistent)?;
            }
            steps.push(MemoryStep { node_id: node.id().to_owned(), produced: node.outputs().to_vec(),
                release_after: std::mem::take(&mut releases[position]), live_bytes, retained_bytes: resident });
        }
        let mut output_bytes = 0;
        for output in graph.outputs() {
            output_bytes = add(output_bytes, values.get(output.name())
                .ok_or(MemoryPlanError::Inconsistent)?.bytes)?;
        }
        checkpoint(&mut cancelled)?;
        let graph_digest = graph.content_digest()?;
        let mut e = CanonicalEncoder::new();
        e.text(MEMORY_PLAN_DOMAIN); e.digest(graph_digest);
        for count in [input_bytes, cumulative_bytes, peak_live_bytes, output_bytes, steps.len()] {
            e.u64(count as u64);
        }
        for step in &steps {
            e.text(&step.node_id); e.u64(step.live_bytes as u64); e.u64(step.retained_bytes as u64);
            for names in [&step.produced, &step.release_after] {
                e.u64(names.len() as u64);
                for name in names { e.text(name); }
            }
        }
        let digest = ContentDigest::sha256(&e.finish());
        checkpoint(&mut cancelled)?;
        Ok(Self { graph: graph_digest, digest, values, steps, input_bytes,
            cumulative_bytes, peak_live_bytes, output_bytes })
    }
    /// Exact canonical graph identity; execution must check it, not only dimensions.
    pub fn graph_digest(&self) -> ContentDigest { self.graph }
    /// Identity of the complete materializing schedule, independent of admission ceilings.
    pub fn digest(&self) -> ContentDigest { self.digest }
    /// Canonical node execution and release boundaries.
    pub fn steps(&self) -> &[MemoryStep] { &self.steps }
    /// Complete inferred value table; no dead value was silently elided.
    pub fn values(&self) -> &BTreeMap<String, TensorLifetime> { &self.values }
    /// Logical caller-owned input payload retained throughout execution.
    pub fn input_bytes(&self) -> usize { self.input_bytes }
    /// Inputs plus EVERY materialized output, preserving cumulative accounting.
    pub fn cumulative_bytes(&self) -> usize { self.cumulative_bytes }
    /// Maximum simultaneously resident logical tensor payload, excluding kernel scratch.
    pub fn peak_live_bytes(&self) -> usize { self.peak_live_bytes }
    /// Complete declared output payload, including pass-through graph inputs.
    pub fn output_bytes(&self) -> usize { self.output_bytes }
    /// Peak when the backend reserves the supplied ADDITIONAL scratch for each step.
    /// Scratch must include all temporary buffers, not the already-counted result tensor.
    /// The backend must bind its scratch policy and actual input backing storage separately.
    pub fn peak_with_scratch(&self, scratch: &[usize]) -> Result<usize, MemoryPlanError> {
        if scratch.len() != self.steps.len() { return Err(MemoryPlanError::ScratchLength); }
        self.steps.iter().zip(scratch).try_fold(self.input_bytes, |peak, (step, bytes)| {
            Ok(peak.max(add(step.live_bytes, *bytes)?))
        })
    }
}

fn add(a: usize, b: usize) -> Result<usize, MemoryPlanError> {
    a.checked_add(b).ok_or(MemoryPlanError::Overflow)
}
fn checkpoint(cancelled: &mut impl FnMut() -> bool) -> Result<(), MemoryPlanError> {
    if cancelled() { Err(MemoryPlanError::Cancelled) } else { Ok(()) }
}
fn payload_bytes(port: &TensorPort) -> Result<usize, MemoryPlanError> {
    let bytes = port.shape().size_bytes(port.dtype())?;
    if bytes > MAX_STORAGE_BYTES { return Err(MemoryPlanError::Limit("tensor payload")); }
    Ok(bytes)
}
fn charge(total: &mut usize, amount: usize, ceiling: usize, kind: &'static str)
    -> Result<(), MemoryPlanError> {
    *total = add(*total, amount)?;
    if *total > ceiling { Err(MemoryPlanError::Limit(kind)) } else { Ok(()) }
}
fn admit(graph: &ModelIrGraph, limits: MemoryPlanLimits, cancelled: &mut impl FnMut() -> bool)
    -> Result<(), MemoryPlanError> {
    if limits.max_nodes > MAX_MEMORY_PLAN_NODES || limits.max_values > MAX_MEMORY_PLAN_VALUES
        || limits.max_references > MAX_MEMORY_PLAN_REFERENCES
        || limits.max_metadata_bytes > MAX_MEMORY_PLAN_METADATA_BYTES {
        return Err(MemoryPlanError::Limit("invalid ceilings"));
    }
    if graph.nodes().len() > limits.max_nodes { return Err(MemoryPlanError::Limit("nodes")); }
    let mut values = graph.inputs().len();
    if values > limits.max_values { return Err(MemoryPlanError::Limit("values")); }
    let mut references = 0;
    let mut metadata = 0;
    charge(&mut metadata, graph.id().len(), limits.max_metadata_bytes, "metadata")?;
    for port in graph.inputs().iter().chain(graph.outputs()) {
        checkpoint(cancelled)?;
        charge(&mut references, 1, limits.max_references, "references")?;
        charge(&mut metadata, add(port.name().len(), port.rank() * 8)?, limits.max_metadata_bytes, "metadata")?;
    }
    for node in graph.nodes() {
        checkpoint(cancelled)?;
        charge(&mut values, node.outputs().len(), limits.max_values, "values")?;
        charge(&mut metadata, add(node.id().len(), node.name().len())?, limits.max_metadata_bytes, "metadata")?;
        for name in node.inputs().iter().chain(node.outputs()) {
            charge(&mut references, 1, limits.max_references, "references")?;
            charge(&mut metadata, name.len(), limits.max_metadata_bytes, "metadata")?;
        }
        for (name, value) in node.attributes() {
            checkpoint(cancelled)?;
            let bytes = match value {
                AttrValue::Bool(_) | AttrValue::DType(_) => 1,
                AttrValue::Int(_) | AttrValue::Float(_) => 8,
                AttrValue::String(value) => value.len(),
                AttrValue::IntList(value) => value.len().checked_mul(8).ok_or(MemoryPlanError::Overflow)?,
                AttrValue::FloatList(value) => value.len().checked_mul(8).ok_or(MemoryPlanError::Overflow)?,
                AttrValue::Shape(value) => value.rank() * 8,
            };
            charge(&mut metadata, add(add(name.len(), bytes)?, 8)?, limits.max_metadata_bytes, "metadata")?;
        }
    }
    Ok(())
}

#![forbid(unsafe_code)]
//! Prepared, optimized CPU execution of frozen F32 Model IR graphs (fss-bd99t).
//!
//! [`OptimizedGraph`] is an alternative execution path ALONGSIDE the scalar reference
//! ([`crate::ScalarExecutor`]), never a replacement. Its numeric contract is the strongest one
//! available: every output element is produced by exactly the same sequence of IEEE-754
//! operations as the reference kernel, so outputs are bit-identical (tolerance zero; NaN outputs
//! occur at the same positions, while NaN payload bits are not asserted because Rust does not
//! specify them). The speed comes from:
//!
//! * weights packed once at preparation into register-tile panels bound into this immutable
//!   prepared object (never re-materialized per inference);
//! * Conv2d as per-output-row GEMM tiles (`MR x NR` independent accumulators), 1x1 convolutions
//!   flattened to one long row, depthwise convolution as whole-row accumulation, all reducing
//!   over the reference's `(cin_g, kh, kw)` order and skipping padded taps exactly;
//! * fused bias + SiLU when a convolution's only consumer is a SiLU node;
//! * SiLU's binary64 series evaluated for several independent elements at once;
//! * liveness-planned activation release and one reused scratch buffer.
//!
//! Operators or geometries outside these kernels run the scalar reference kernel for that node,
//! and that choice is recorded per node in the prepared plan identity (never silent).
//! Differential tests against the scalar kernels live in `optimized_executor/tests.rs`.

use std::collections::BTreeMap;

use fss_core::{CanonicalEncoder, ContentDigest, Generation};
use fss_model_ir::{
    GraphNode, GraphValidator, ModelIrGraph, ModelIrVersion, OpCode, ProducerId, TensorPort,
    encode_canonical_model_ir, infer_operator_outputs,
};
use fss_tensor::{DType, Tensor};

use crate::scalar_executor::compute_node_macs;
use crate::{ExecBudget, ExecError, ExecOutcome, ScalarExecCx, ScalarExecutor};

mod conv;
mod layout;
mod pointwise;
#[cfg(test)]
mod tests;

/// Digest domain of the optimized executor's kernel generation and prepared plans.
pub const OPTIMIZED_EXECUTOR_DOMAIN: &str = "fss.reference.optimized_executor.v1";

/// Which kernel family executes a model. Every identity that depends on model outputs binds it,
/// so evidence produced by different kernel generations never mixes silently.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum KernelBackend {
    /// The deterministic scalar reference executor (the semantic oracle).
    ScalarReference,
    /// The prepared optimized CPU executor, certified bit-identical to the scalar reference.
    OptimizedCpuV1,
}

impl KernelBackend {
    /// Stable identifier recorded in identities and reports.
    #[must_use]
    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::ScalarReference => "scalar-reference.v1",
            Self::OptimizedCpuV1 => "optimized-cpu.v1",
        }
    }

    /// Kernel-generation digest (implementation identity, independent of any model).
    #[must_use]
    pub fn generation(self) -> ContentDigest {
        match self {
            Self::ScalarReference => scalar_kernel_generation(),
            Self::OptimizedCpuV1 => optimized_kernel_generation(),
        }
    }
}

/// Source identity of the scalar reference kernels.
#[must_use]
pub fn scalar_kernel_generation() -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(OPTIMIZED_EXECUTOR_DOMAIN);
    e.text(KernelBackend::ScalarReference.stable_id());
    for source in [
        include_bytes!("scalar_executor.rs").as_slice(),
        include_bytes!("../../fss-tensor/src/tensor.rs").as_slice(),
        include_bytes!("../../fss-model-ir/src/shape_inference.rs").as_slice(),
    ] {
        e.digest(ContentDigest::sha256(source));
    }
    ContentDigest::sha256(&e.finish())
}

/// Source and tiling identity of the optimized kernels, including the scalar kernels they
/// reuse for tails, border columns and reference-kernel nodes.
#[must_use]
pub fn optimized_kernel_generation() -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text(OPTIMIZED_EXECUTOR_DOMAIN);
    e.text(KernelBackend::OptimizedCpuV1.stable_id());
    e.u64(conv::MR as u64);
    e.u64(conv::NR as u64);
    e.u64(pointwise::SILU_LANES as u64);
    for source in [
        include_bytes!("optimized_executor.rs").as_slice(),
        include_bytes!("optimized_executor/conv.rs").as_slice(),
        include_bytes!("optimized_executor/pointwise.rs").as_slice(),
        include_bytes!("optimized_executor/layout.rs").as_slice(),
    ] {
        e.digest(ContentDigest::sha256(source));
    }
    e.digest(scalar_kernel_generation());
    ContentDigest::sha256(&e.finish())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Source {
    Slot(usize),
    Const(usize),
}

#[derive(Clone, Debug)]
struct ReferenceNode {
    program: ModelIrGraph,
    output: String,
}

#[derive(Clone, Debug)]
enum Kernel {
    Conv(Box<conv::PreparedConv>),
    Silu,
    Sigmoid,
    Relu,
    Binary(pointwise::BinaryOp, pointwise::Broadcast),
    Pool(pointwise::Pool),
    Gather(layout::Gather),
    Concat(layout::Concat),
    Copy,
    Reference(Box<ReferenceNode>),
}

impl Kernel {
    fn label(&self) -> &'static str {
        match self {
            Self::Conv(c) => c.label(),
            Self::Silu => "silu.lanes8.v1",
            Self::Sigmoid => "sigmoid.map.v1",
            Self::Relu => "relu.map.v1",
            Self::Binary(op, _) => op.label(),
            Self::Pool(_) => "maxpool2d.direct.v1",
            Self::Gather(_) => "gather.strided-runs.v1",
            Self::Concat(_) => "concat.blocks.v1",
            Self::Copy => "reshape.copy.v1",
            Self::Reference(_) => "scalar-reference-node.v1",
        }
    }
}

#[derive(Clone, Debug)]
struct Step {
    node_id: String,
    op: OpCode,
    kernel: Kernel,
    sources: Vec<Source>,
    output: usize,
    output_len: usize,
    release: Vec<usize>,
}

/// Measured resource witness of one optimized run (tensor payload, not process RSS).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OptimizedRunReport {
    /// Highest live activation payload plus kernel scratch observed at any step.
    pub peak_live_bytes: usize,
    /// Largest kernel scratch buffer used.
    pub scratch_bytes: usize,
    /// Constants and packed weights resident in the prepared plan (not per-run).
    pub resident_bytes: usize,
}

/// Immutable prepared graph: validated schedule, per-node kernel choices, packed weights.
/// Its identity ([`OptimizedGraph::digest`]) names the kernel generation, the exact graph, the
/// bound constants and every per-node kernel/fusion choice.
#[derive(Clone, Debug)]
pub struct OptimizedGraph {
    generation: Generation,
    runtime_inputs: Vec<(TensorPort, usize)>,
    constants: Vec<Vec<f32>>,
    outputs: Vec<(TensorPort, Source)>,
    steps: Vec<Step>,
    slot_count: usize,
    total_macs: u64,
    total_bytes: usize,
    node_count: usize,
    kernel_generation: ContentDigest,
    digest: ContentDigest,
    resident_bytes: usize,
}

fn mismatch(node_id: &str, op_id: &'static str, reason: &str) -> ExecError {
    ExecError::ShapeMismatch {
        node_id: node_id.to_owned(),
        op_id,
        reason: reason.to_owned(),
    }
}

impl OptimizedGraph {
    /// Validate the complete graph exactly like the scalar reference's preflight, bind the
    /// constant inputs (for example model weights), choose a kernel per node and pack weights.
    /// Graph inputs not named in `constants` are supplied per run. F32 only.
    pub fn prepare(
        graph: &ModelIrGraph,
        constants: &BTreeMap<String, Vec<f32>>,
        cx: &ScalarExecCx,
    ) -> Result<Self, ExecError> {
        cx.checkpoint("optimized:prepare")?;
        let expected_version = ModelIrVersion::from_u32(1).map_err(ExecError::Ir)?;
        if graph.version() != expected_version {
            return Err(ExecError::UnsupportedVersion {
                expected: 1,
                actual: graph.version().as_u32(),
            });
        }
        GraphValidator::validate(graph).map_err(ExecError::Ir)?;
        let mut producer_map = BTreeMap::new();
        for input in graph.inputs() {
            producer_map.insert(input.name(), ProducerId::GraphInput);
        }
        for node in graph.nodes() {
            for out_name in node.outputs() {
                producer_map.insert(out_name.as_str(), ProducerId::Node(node.id()));
            }
        }
        let sorted =
            GraphValidator::topological_sort(graph, &producer_map).map_err(ExecError::Ir)?;
        for port in graph.inputs().iter().chain(graph.outputs()) {
            if port.dtype() != DType::F32 {
                return Err(ExecError::UnsupportedDType {
                    expected: DType::F32,
                    actual: port.dtype(),
                    tensor_name: port.name().to_owned(),
                });
            }
        }
        for name in constants.keys() {
            if graph.find_input(name).is_none() {
                return Err(mismatch(
                    "input",
                    "graph_input",
                    "constant is not a graph input",
                ));
            }
        }

        let mut ports: BTreeMap<String, TensorPort> = BTreeMap::new();
        let mut sources: BTreeMap<String, Source> = BTreeMap::new();
        let mut constant_values = Vec::new();
        let mut runtime_inputs = Vec::new();
        let mut slot_count = 0_usize;
        let mut total_bytes = 0_usize;
        for input in graph.inputs() {
            ports.insert(input.name().to_owned(), input.clone());
            total_bytes = total_bytes
                .checked_add(input.shape().size_bytes(input.dtype())?)
                .ok_or(ExecError::ArithmeticOverflow {
                    operation: "input tensor bytes accumulation",
                })?;
            match constants.get(input.name()) {
                Some(values) => {
                    if values.len() != input.shape().num_elements()? {
                        return Err(mismatch("input", "graph_input", "constant element count"));
                    }
                    sources.insert(
                        input.name().to_owned(),
                        Source::Const(constant_values.len()),
                    );
                    constant_values.push(values.clone());
                }
                None => {
                    sources.insert(input.name().to_owned(), Source::Slot(slot_count));
                    runtime_inputs.push((input.clone(), slot_count));
                    slot_count += 1;
                }
            }
        }

        // Shape inference, work and cumulative-byte accounting identical to the reference.
        let mut out_ports: Vec<Vec<TensorPort>> = Vec::with_capacity(sorted.len());
        let mut total_macs = 0_u64;
        for node in &sorted {
            let inputs: Vec<TensorPort> = node
                .inputs()
                .iter()
                .map(|n| {
                    ports.get(n).cloned().ok_or_else(|| {
                        mismatch(
                            node.id(),
                            node.op().stable_id(),
                            "missing intermediate tensor port",
                        )
                    })
                })
                .collect::<Result<_, _>>()?;
            let refs: Vec<&TensorPort> = inputs.iter().collect();
            let outs = infer_operator_outputs(
                node.id(),
                node.op(),
                &refs,
                node.outputs(),
                node.attributes(),
                graph.generation(),
            )?;
            for port in &outs {
                if port.dtype() != DType::F32 {
                    return Err(ExecError::UnsupportedDType {
                        expected: DType::F32,
                        actual: port.dtype(),
                        tensor_name: port.name().to_owned(),
                    });
                }
                total_bytes = total_bytes
                    .checked_add(port.shape().size_bytes(port.dtype())?)
                    .ok_or(ExecError::ArithmeticOverflow {
                        operation: "total output bytes accumulation",
                    })?;
                ports.insert(port.name().to_owned(), port.clone());
                sources.insert(port.name().to_owned(), Source::Slot(slot_count));
                slot_count += 1;
            }
            total_macs = total_macs
                .checked_add(compute_node_macs(node, &inputs, &outs)?)
                .ok_or(ExecError::ArithmeticOverflow {
                    operation: "total MACs accumulation",
                })?;
            out_ports.push(outs);
        }

        let output_names: Vec<&str> = graph.outputs().iter().map(TensorPort::name).collect();
        let mut uses: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for (index, node) in sorted.iter().enumerate() {
            for name in node.inputs() {
                uses.entry(name.as_str()).or_default().push(index);
            }
        }

        let mut fused = vec![false; sorted.len()];
        let mut steps = Vec::with_capacity(sorted.len());
        for (index, node) in sorted.iter().enumerate() {
            cx.checkpoint("optimized:prepare-node")?;
            if fused[index] {
                continue;
            }
            let outs = &out_ports[index];
            let [out] = outs.as_slice() else {
                return Err(mismatch(
                    node.id(),
                    node.op().stable_id(),
                    "single output required",
                ));
            };
            let port = |name: &str| lookup(&ports, node, name);
            let source = |name: &String| -> Result<Source, ExecError> {
                sources
                    .get(name)
                    .copied()
                    .ok_or_else(|| mismatch(node.id(), node.op().stable_id(), "missing value"))
            };
            let constant = |name: &String| constant_of(&sources, &constant_values, name);
            let mut output_name = out.name().to_owned();
            let mut step_sources: Vec<Source> =
                node.inputs().iter().map(source).collect::<Result<_, _>>()?;
            let in_dims = |i: usize| -> Result<Vec<usize>, ExecError> {
                Ok(port(node.inputs()[i].as_str())?.shape().dims().to_vec())
            };
            let out_dims = out.shape().dims();
            let kernel = match node.op() {
                OpCode::Conv2d => {
                    let prepared = match (
                        node.inputs().get(1).and_then(constant),
                        node.inputs().get(2).map(constant),
                    ) {
                        (Some(w), bias) if !matches!(bias, Some(None)) => {
                            conv::PreparedConv::prepare(
                                node,
                                port(node.inputs()[0].as_str())?,
                                (port(node.inputs()[1].as_str())?, w),
                                bias.flatten(),
                                out,
                            )?
                        }
                        _ => None,
                    };
                    match prepared {
                        Some(mut conv) => {
                            // Fuse bias + SiLU when this output's only use is one SiLU node.
                            let consumers = uses.get(out.name()).map(Vec::as_slice).unwrap_or(&[]);
                            if let [only] = consumers
                                && sorted[*only].op() == OpCode::Silu
                                && sorted[*only].inputs().len() == 1
                                && !output_names.contains(&out.name())
                            {
                                conv.silu = true;
                                fused[*only] = true;
                                output_name = sorted[*only].outputs()[0].clone();
                            }
                            step_sources.truncate(1);
                            Kernel::Conv(Box::new(conv))
                        }
                        None => reference(node, graph, &ports)?,
                    }
                }
                OpCode::Silu => Kernel::Silu,
                OpCode::Sigmoid => Kernel::Sigmoid,
                OpCode::Relu => Kernel::Relu,
                OpCode::Add | OpCode::Sub | OpCode::Mul | OpCode::Div => {
                    match pointwise::BinaryOp::of(node.op()) {
                        Some(op) if node.inputs().len() == 2 => Kernel::Binary(
                            op,
                            pointwise::Broadcast::new(&in_dims(0)?, &in_dims(1)?, out_dims),
                        ),
                        _ => reference(node, graph, &ports)?,
                    }
                }
                OpCode::MaxPool2d => match pointwise::Pool::new(node, &in_dims(0)?, out_dims)? {
                    Some(pool) => Kernel::Pool(pool),
                    None => reference(node, graph, &ports)?,
                },
                OpCode::Transpose | OpCode::Slice => {
                    match layout::Gather::new(node, &in_dims(0)?, out_dims)? {
                        Some(g) => Kernel::Gather(g),
                        None => reference(node, graph, &ports)?,
                    }
                }
                OpCode::Concat => {
                    let dims: Vec<Vec<usize>> = (0..node.inputs().len())
                        .map(in_dims)
                        .collect::<Result<_, _>>()?;
                    let refs: Vec<&[usize]> = dims.iter().map(Vec::as_slice).collect();
                    match layout::Concat::new(node, &refs, out_dims)? {
                        Some(c) => Kernel::Concat(c),
                        None => reference(node, graph, &ports)?,
                    }
                }
                OpCode::Reshape | OpCode::Squeeze | OpCode::Unsqueeze => Kernel::Copy,
                OpCode::Gelu
                | OpCode::Tanh
                | OpCode::MatMul
                | OpCode::LayerNorm
                | OpCode::RMSNorm
                | OpCode::Softmax
                | OpCode::Embedding => reference(node, graph, &ports)?,
            };
            let Some(Source::Slot(output)) = sources.get(&output_name).copied() else {
                return Err(mismatch(node.id(), node.op().stable_id(), "output slot"));
            };
            steps.push(Step {
                node_id: node.id().to_owned(),
                op: node.op(),
                kernel,
                sources: step_sources,
                output,
                output_len: out.shape().num_elements()?,
                release: Vec::new(),
            });
        }

        // Liveness: release every slot after its last reading step unless it is a graph output.
        let mut outputs = Vec::with_capacity(graph.outputs().len());
        let mut keep = vec![false; slot_count];
        for port in graph.outputs() {
            let s = sources.get(port.name()).copied().ok_or_else(|| {
                mismatch("output", "graph_output", "declared output not generated")
            })?;
            if let Source::Slot(slot) = s {
                keep[slot] = true;
            }
            outputs.push((port.clone(), s));
        }
        let mut last = vec![None; slot_count];
        for (index, step) in steps.iter().enumerate() {
            for s in &step.sources {
                if let Source::Slot(slot) = s {
                    last[*slot] = Some(index);
                }
            }
        }
        for (slot, step) in last.iter().enumerate() {
            if let Some(step) = step
                && !keep[slot]
            {
                steps[*step].release.push(slot);
            }
        }

        let kernel_generation = optimized_kernel_generation();
        let mut e = CanonicalEncoder::new();
        e.text(OPTIMIZED_EXECUTOR_DOMAIN);
        e.text("plan");
        e.digest(kernel_generation);
        e.digest(ContentDigest::sha256(
            &encode_canonical_model_ir(graph).map_err(ExecError::Ir)?,
        ));
        e.u64(constants.len() as u64);
        for (name, values) in constants {
            cx.checkpoint("optimized:prepare-digest")?;
            e.text(name);
            e.u64(values.len() as u64);
            let bytes: Vec<u8> = values
                .iter()
                .flat_map(|v| v.to_bits().to_le_bytes())
                .collect();
            e.digest(ContentDigest::sha256(&bytes));
        }
        e.u64(steps.len() as u64);
        for step in &steps {
            e.text(&step.node_id);
            e.text(step.op.stable_id());
            e.text(step.kernel.label());
        }
        let digest = ContentDigest::sha256(&e.finish());
        let resident_bytes = constant_values.iter().map(|v| v.len() * 4).sum::<usize>()
            + steps
                .iter()
                .map(|s| match &s.kernel {
                    Kernel::Conv(c) => c.resident_bytes(),
                    Kernel::Silu
                    | Kernel::Sigmoid
                    | Kernel::Relu
                    | Kernel::Binary(..)
                    | Kernel::Pool(_)
                    | Kernel::Gather(_)
                    | Kernel::Concat(_)
                    | Kernel::Copy
                    | Kernel::Reference(_) => 0,
                })
                .sum::<usize>();
        cx.checkpoint("optimized:prepared")?;
        Ok(Self {
            generation: graph.generation(),
            runtime_inputs,
            constants: constant_values,
            outputs,
            steps,
            slot_count,
            total_macs,
            total_bytes,
            node_count: sorted.len(),
            kernel_generation,
            digest,
            resident_bytes,
        })
    }

    /// Always [`KernelBackend::OptimizedCpuV1`].
    #[must_use]
    pub fn backend(&self) -> KernelBackend {
        KernelBackend::OptimizedCpuV1
    }
    /// Implementation identity of the kernels that run.
    #[must_use]
    pub fn kernel_generation(&self) -> ContentDigest {
        self.kernel_generation
    }
    /// Prepared-plan identity: kernel generation, graph, constants and per-node kernel choices.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Number of executed steps per kernel label (fused SiLU nodes do not form steps).
    #[must_use]
    pub fn kernel_counts(&self) -> BTreeMap<&'static str, usize> {
        let mut counts = BTreeMap::new();
        for step in &self.steps {
            *counts.entry(step.kernel.label()).or_insert(0) += 1;
        }
        counts
    }
    /// Graph inputs supplied per run (everything that is not a bound constant).
    #[must_use]
    pub fn runtime_inputs(&self) -> Vec<&TensorPort> {
        self.runtime_inputs.iter().map(|(p, _)| p).collect()
    }

    /// Execute once. Bindings, budget admission and the returned work/byte accounting are
    /// identical to [`ScalarExecutor::run`] on the same graph with the constants supplied.
    pub fn run<S: AsRef<str>>(
        &self,
        inputs: &[(S, Tensor)],
        budget: ExecBudget,
        cx: &ScalarExecCx,
    ) -> Result<ExecOutcome, ExecError> {
        self.run_with_report(inputs, budget, cx).map(|(o, _)| o)
    }

    /// Execute once and also return the measured payload witness.
    pub fn run_with_report<S: AsRef<str>>(
        &self,
        inputs: &[(S, Tensor)],
        budget: ExecBudget,
        cx: &ScalarExecCx,
    ) -> Result<(ExecOutcome, OptimizedRunReport), ExecError> {
        cx.checkpoint("pre-execution")?;
        let mut bound: BTreeMap<&str, &Tensor> = BTreeMap::new();
        for (name, tensor) in inputs {
            let name = name.as_ref();
            if !self.runtime_inputs.iter().any(|(p, _)| p.name() == name) {
                return Err(mismatch(
                    "input",
                    "graph_input",
                    &format!("unexpected input port '{name}'"),
                ));
            }
            if bound.insert(name, tensor).is_some() {
                return Err(mismatch(
                    "input",
                    "graph_input",
                    &format!("duplicate input port '{name}'"),
                ));
            }
        }
        let mut env: Vec<Option<Vec<f32>>> = vec![None; self.slot_count];
        let mut peak = 0_usize;
        for (port, _) in &self.runtime_inputs {
            let tensor = bound
                .get(port.name())
                .ok_or_else(|| ExecError::MissingInputPort {
                    expected_port: port.name().to_owned(),
                })?;
            if tensor.dtype() != port.dtype() {
                return Err(ExecError::UnsupportedDType {
                    expected: port.dtype(),
                    actual: tensor.dtype(),
                    tensor_name: port.name().to_owned(),
                });
            }
            if tensor.shape() != port.shape() {
                return Err(mismatch(
                    "input",
                    "graph_input",
                    &format!(
                        "input port '{}' expected shape {:?}, got {:?}",
                        port.name(),
                        port.shape().dims(),
                        tensor.shape().dims()
                    ),
                ));
            }
            if tensor.generation() != self.generation {
                return Err(ExecError::GenerationMismatch {
                    expected: self.generation,
                    actual: tensor.generation(),
                    tensor_name: port.name().to_owned(),
                });
            }
        }
        if self.total_macs > budget.max_macs || self.total_bytes > budget.max_bytes {
            return Err(ExecError::BudgetExceeded {
                macs: self.total_macs,
                max_macs: budget.max_macs,
                bytes: self.total_bytes,
                max_bytes: budget.max_bytes,
            });
        }
        for (port, slot) in &self.runtime_inputs {
            if let Some(tensor) = bound.get(port.name()) {
                let values = tensor.to_vec::<f32>()?;
                peak += values.len() * 4;
                env[*slot] = Some(values);
            }
        }
        let mut scratch: Vec<f32> = Vec::new();
        let mut scratch_peak = 0_usize;
        for step in &self.steps {
            cx.checkpoint("node-execution")?;
            let mut out = Vec::new();
            self.execute(step, &mut env, &mut out, &mut scratch, cx)?;
            if out.len() != step.output_len {
                return Err(mismatch(
                    &step.node_id,
                    step.op.stable_id(),
                    "output element count",
                ));
            }
            // Everything resident at this instant: live activations, the new output, scratch.
            let live: usize =
                env.iter().flatten().map(|v| v.len() * 4).sum::<usize>() + out.len() * 4;
            scratch_peak = scratch_peak.max(scratch.capacity() * 4);
            peak = peak.max(live + scratch.capacity() * 4);
            env[step.output] = Some(out);
            for slot in &step.release {
                env[*slot] = None;
            }
        }
        let mut outputs = BTreeMap::new();
        for (port, source) in &self.outputs {
            let values = self.value(&env, *source)?;
            outputs.insert(
                port.name().to_owned(),
                Tensor::from_values(port.shape().clone(), values, self.generation)?,
            );
        }
        cx.checkpoint("publish-outputs")?;
        Ok((
            ExecOutcome::new(outputs, self.total_macs, self.total_bytes, self.node_count),
            OptimizedRunReport {
                peak_live_bytes: peak,
                scratch_bytes: scratch_peak,
                resident_bytes: self.resident_bytes,
            },
        ))
    }

    fn value<'a>(&'a self, env: &'a [Option<Vec<f32>>], s: Source) -> Result<&'a [f32], ExecError> {
        match s {
            Source::Const(c) => self.constants.get(c).map(Vec::as_slice),
            Source::Slot(slot) => env.get(slot).and_then(Option::as_deref),
        }
        .ok_or_else(|| mismatch("optimized", "optimized_value", "value not live"))
    }

    fn execute(
        &self,
        step: &Step,
        env: &mut [Option<Vec<f32>>],
        out: &mut Vec<f32>,
        scratch: &mut Vec<f32>,
        cx: &ScalarExecCx,
    ) -> Result<(), ExecError> {
        let first = |env: &[Option<Vec<f32>>]| -> Result<Vec<f32>, ExecError> {
            Ok(self.value(env, step.sources[0])?.to_vec())
        };
        match &step.kernel {
            Kernel::Conv(conv) => {
                out.resize(conv.output_len(), 0.0);
                conv.run(self.value(env, step.sources[0])?, out, scratch, cx)?;
            }
            Kernel::Silu => {
                *out = first(env)?;
                pointwise::silu_in_place(out);
            }
            Kernel::Sigmoid => {
                let x = self.value(env, step.sources[0])?;
                out.extend(x.iter().map(|v| crate::deterministic_sigmoid_f32(*v)));
            }
            Kernel::Relu => {
                let x = self.value(env, step.sources[0])?;
                out.extend(x.iter().map(|&v| if v > 0.0_f32 { v } else { 0.0_f32 }));
            }
            Kernel::Binary(op, plan) => {
                let a = self.value(env, step.sources[0])?;
                let b = self.value(env, step.sources[1])?;
                plan.run(*op, a, b, out);
            }
            Kernel::Pool(pool) => pool.run(self.value(env, step.sources[0])?, out),
            Kernel::Gather(gather) => gather.run(self.value(env, step.sources[0])?, out),
            Kernel::Concat(concat) => {
                let parts: Vec<&[f32]> = step
                    .sources
                    .iter()
                    .map(|s| self.value(env, *s))
                    .collect::<Result<_, _>>()?;
                concat.run(&parts, out);
            }
            Kernel::Copy => match step.sources[0] {
                // Last use of an activation: move the buffer instead of copying it.
                Source::Slot(slot) if step.release.contains(&slot) => {
                    *out = env[slot].take().ok_or_else(|| {
                        mismatch(&step.node_id, step.op.stable_id(), "value not live")
                    })?;
                }
                Source::Slot(_) | Source::Const(_) => *out = first(env)?,
            },
            Kernel::Reference(node) => {
                let args: Vec<(String, Tensor)> = node
                    .program
                    .inputs()
                    .iter()
                    .map(|port| {
                        let index = step_input_index(step, &node.program, port.name())?;
                        let values = self.value(env, step.sources[index])?;
                        Ok((
                            port.name().to_owned(),
                            Tensor::from_values(port.shape().clone(), values, self.generation)?,
                        ))
                    })
                    .collect::<Result<_, ExecError>>()?;
                let result =
                    ScalarExecutor::run(&node.program, &args, ExecBudget::unlimited(), cx)?;
                *out = result
                    .get_output(&node.output)
                    .ok_or_else(|| {
                        mismatch(&step.node_id, step.op.stable_id(), "reference output")
                    })?
                    .to_vec::<f32>()?;
            }
        }
        Ok(())
    }
}

fn lookup<'a>(
    ports: &'a BTreeMap<String, TensorPort>,
    node: &GraphNode,
    name: &str,
) -> Result<&'a TensorPort, ExecError> {
    ports
        .get(name)
        .ok_or_else(|| mismatch(node.id(), node.op().stable_id(), "missing port"))
}

fn constant_of<'a>(
    sources: &BTreeMap<String, Source>,
    constants: &'a [Vec<f32>],
    name: &str,
) -> Option<&'a [f32]> {
    match sources.get(name) {
        Some(Source::Const(c)) => constants.get(*c).map(Vec::as_slice),
        Some(Source::Slot(_)) | None => None,
    }
}

/// Position of a program input among the node's (possibly repeated) input names.
fn step_input_index(step: &Step, program: &ModelIrGraph, name: &str) -> Result<usize, ExecError> {
    program
        .nodes()
        .first()
        .and_then(|n| n.inputs().iter().position(|i| i == name))
        .ok_or_else(|| mismatch(&step.node_id, step.op.stable_id(), "reference input"))
}

/// One-node program executed by the unchanged scalar reference kernel.
fn reference(
    node: &GraphNode,
    graph: &ModelIrGraph,
    ports: &BTreeMap<String, TensorPort>,
) -> Result<Kernel, ExecError> {
    let mut unique = BTreeMap::new();
    for name in node.inputs() {
        let port = ports
            .get(name)
            .ok_or_else(|| mismatch(node.id(), node.op().stable_id(), "missing port"))?;
        unique.insert(name.clone(), port.clone());
    }
    let outputs: Vec<TensorPort> = node
        .outputs()
        .iter()
        .map(|n| {
            ports
                .get(n)
                .cloned()
                .ok_or_else(|| mismatch(node.id(), node.op().stable_id(), "missing port"))
        })
        .collect::<Result<_, _>>()?;
    let output = node
        .outputs()
        .first()
        .cloned()
        .ok_or_else(|| mismatch(node.id(), node.op().stable_id(), "single output required"))?;
    let program = ModelIrGraph::new_validated(
        "fss:optimized:reference-node:v1",
        ModelIrVersion::V1,
        graph.generation(),
        unique.into_values().collect(),
        outputs,
        vec![node.clone()],
    )
    .map_err(ExecError::Ir)?;
    Ok(Kernel::Reference(Box::new(ReferenceNode {
        program,
        output,
    })))
}

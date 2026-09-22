#![forbid(unsafe_code)]
//! Reusable bounded liveness execution over the existing scalar kernel backend.
//!
//! Compile the complete graph first. Execute canonical one-node IR programs with
//! the unchanged scalar backend, then release last-use activations. This preserves
//! numerical order and error semantics without maintaining a second kernel set.
//! Node-program validation overhead remains deliberate in this reference path.
//! Peak budgets cover tensor/scratch payload, not allocator overhead or process RSS.

use std::collections::BTreeMap;
use fss_core::{CanonicalEncoder, ContentDigest};
use fss_model_ir::{MemoryPlan, MemoryPlanError, MemoryPlanLimits, ModelIrGraph,
    ModelIrVersion, OpCode, TensorPort};
use fss_tensor::{DType, Tensor};
use crate::{ExecBudget, ExecError, ExecOutcome, ScalarExecCx, ScalarExecutor};

mod budget;

/// Versioned compilation, backend and scratch-accounting policy.
pub const PLANNED_SCALAR_DOMAIN: &str = "fss.reference.planned_scalar.v1";

/// Explicit peak-payload budget; never reinterprets the legacy cumulative byte limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeakExecBudget {
    /// Whole-graph reference work, using the scalar backend's logical work units.
    pub max_macs: u64,
    /// Maximum resident tensor plus temporary kernel payload at any one node.
    pub max_peak_bytes: usize,
    /// Independent ceiling on additional temporary kernel payload at any node.
    pub max_scratch_bytes: usize,
}
impl PeakExecBudget {
    /// Set all three bounds; zero is allowed for genuinely empty work/payload.
    pub const fn new(max_macs: u64, max_peak_bytes: usize, max_scratch_bytes: usize) -> Self {
        Self { max_macs, max_peak_bytes, max_scratch_bytes }
    }
}

/// Complete admission requirements for the actual supplied input backing buffers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScalarMemoryRequirements {
    /// Whole-graph logical work, checked again against every backend result.
    pub macs: u64,
    /// Peak live tensor payload plus corresponding node scratch.
    pub peak_bytes: usize,
    /// Maximum additional kernel scratch, independent of live tensor payload.
    pub scratch_bytes: usize,
    /// Conservative sum of complete input backing buffers, at least logical input bytes.
    pub input_backing_bytes: usize,
}

/// Fail-closed error: no partial graph outputs or successful receipt are returned.
#[derive(Debug)]
pub enum PlannedExecError {
    /// The complete graph could not be planned.
    Planning(MemoryPlanError),
    /// The unchanged scalar backend refused execution.
    Execution(ExecError),
    /// Missing, duplicate or undeclared input binding; values are never echoed.
    InputSet,
    /// A supplied input has a different dtype, shape or generation.
    InputContract,
    /// Whole-graph work, peak payload or scratch exceeded the explicit budget.
    BudgetExceeded {
        /// Required resources for this invocation.
        required: ScalarMemoryRequirements,
        /// Caller-selected ceilings.
        budget: PeakExecBudget,
    },
    /// Checked byte/work arithmetic overflowed.
    Overflow,
    /// A backend result disagreed with the compiled node contract or cost model.
    BackendMismatch,
}
impl From<MemoryPlanError> for PlannedExecError {
    fn from(e: MemoryPlanError) -> Self { Self::Planning(e) }
}
impl From<ExecError> for PlannedExecError {
    fn from(e: ExecError) -> Self { Self::Execution(e) }
}
impl std::fmt::Display for PlannedExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Planning(_) => "scalar memory planning refused",
            Self::Execution(_) => "planned scalar execution refused",
            Self::InputSet => "planned scalar input binding set mismatch",
            Self::InputContract => "planned scalar input contract mismatch",
            Self::BudgetExceeded { .. } => "planned scalar resource bound exceeded",
            Self::Overflow => "planned scalar resource arithmetic overflow",
            Self::BackendMismatch => "scalar backend disagrees with compiled plan",
        })
    }
}
impl std::error::Error for PlannedExecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Planning(e) => Some(e), Self::Execution(e) => Some(e),
            Self::InputSet | Self::InputContract | Self::BudgetExceeded { .. }
            | Self::Overflow | Self::BackendMismatch => None,
        }
    }
}

#[derive(Clone, Debug)]
struct NodeProgram {
    graph: ModelIrGraph,
    macs: u64,
    cumulative_bytes: usize,
}

/// Immutable compiled graph plus exact materializing schedule and kernel profile.
/// Inputs are supplied per invocation; this type never caches camera or tensor data.
#[derive(Clone, Debug)]
pub struct CompiledScalarPlan {
    memory: MemoryPlan,
    profile: ContentDigest,
    digest: ContentDigest,
    inputs: Vec<TensorPort>,
    outputs: Vec<TensorPort>,
    programs: Vec<NodeProgram>,
    macs: u64,
    peak_bytes: usize,
    scratch_bytes: usize,
}
impl CompiledScalarPlan {
    /// Validate and compile the entire graph without reading any tensor values.
    /// Unsupported dtypes, malformed dead branches and work overflow fail before execution.
    pub fn compile(graph: &ModelIrGraph, limits: MemoryPlanLimits, cx: &ScalarExecCx)
        -> Result<Self, PlannedExecError> {
        cx.checkpoint("memory-plan:begin")?;
        let memory = match MemoryPlan::compile_cancellable(graph, limits, || cx.is_cancelled()) {
            Err(MemoryPlanError::Cancelled) => {
                cx.drain_and_finalize();
                return Err(ExecError::CancellationRequested { stage: "memory-plan:compile" }.into());
            }
            result => result?,
        };
        // Preserve the scalar backend's narrow integer admission across the WHOLE graph.
        // Partitioning may not hide an unsupported consumer in a different node program.
        for input in graph.inputs() {
            if input.dtype() != DType::F32 {
                let mut used = false;
                let mut admitted = input.dtype().is_integer()
                    && !graph.outputs().iter().any(|o| o.name() == input.name());
                for node in graph.nodes() {
                    for (position, name) in node.inputs().iter().enumerate() {
                        if name == input.name() {
                            used = true;
                            admitted &= node.op() == OpCode::Embedding && position == 0;
                        }
                    }
                }
                if !admitted || !used {
                    return Err(ExecError::UnsupportedDType { expected: DType::F32,
                        actual: input.dtype(), tensor_name: input.name().to_owned() }.into());
                }
            }
        }
        for value in memory.values().values() {
            if value.producer().is_some() && value.port().dtype() != DType::F32 {
                return Err(ExecError::UnsupportedDType { expected: DType::F32,
                    actual: value.port().dtype(), tensor_name: value.port().name().to_owned() }.into());
            }
        }
        for output in graph.outputs() {
            if output.dtype() != DType::F32 {
                return Err(ExecError::UnsupportedDType { expected: DType::F32,
                    actual: output.dtype(), tensor_name: output.name().to_owned() }.into());
            }
        }
        let nodes: BTreeMap<_, _> = graph.nodes().iter().map(|node| (node.id(), node)).collect();
        let mut programs = Vec::with_capacity(memory.steps().len());
        let mut scratch = Vec::with_capacity(memory.steps().len());
        let mut macs = 0_u64;
        for step in memory.steps() {
            cx.checkpoint("memory-plan:node")?;
            let node = nodes.get(step.node_id()).ok_or(PlannedExecError::BackendMismatch)?;
            let input_ports: Vec<_> = node.inputs().iter().map(|name| {
                memory.values().get(name).map(|v| v.port().clone()).ok_or(PlannedExecError::BackendMismatch)
            }).collect::<Result<_, _>>()?;
            let output_ports: Vec<_> = node.outputs().iter().map(|name| {
                memory.values().get(name).map(|v| v.port().clone()).ok_or(PlannedExecError::BackendMismatch)
            }).collect::<Result<_, _>>()?;
            let (work, temporary) = budget::node_resources(node, &input_ports, &output_ports)?;
            macs = macs.checked_add(work).ok_or(PlannedExecError::Overflow)?;
            scratch.push(temporary);
            // Node input references may repeat. Graph declarations and bindings must not.
            let unique: BTreeMap<_, _> = input_ports.iter().map(|p| (p.name(), p.clone())).collect();
            let mut cumulative_bytes = 0;
            for port in unique.values().chain(output_ports.iter()) {
                cumulative_bytes = add(cumulative_bytes, bytes(port)?)?;
            }
            let program = ModelIrGraph::new_validated("fss:scalar:node-program:v1",
                ModelIrVersion::V1, graph.generation(), unique.into_values().collect(),
                output_ports, vec![(**node).clone()]).map_err(ExecError::Ir)?;
            programs.push(NodeProgram { graph: program, macs: work, cumulative_bytes });
        }
        let peak_bytes = memory.peak_with_scratch(&scratch)?;
        let scratch_bytes = scratch.iter().copied().max().unwrap_or(0);
        let profile = execution_profile();
        let mut e = CanonicalEncoder::new();
        e.text(PLANNED_SCALAR_DOMAIN); e.digest(memory.digest()); e.digest(profile);
        e.u64(macs); e.u64(peak_bytes as u64); e.u64(scratch_bytes as u64);
        for (program, temporary) in programs.iter().zip(scratch) {
            e.u64(program.macs); e.u64(program.cumulative_bytes as u64); e.u64(temporary as u64);
        }
        let digest = ContentDigest::sha256(&e.finish());
        cx.checkpoint("memory-plan:sealed")?;
        Ok(Self { memory, profile, digest, inputs: graph.inputs().to_vec(),
            outputs: graph.outputs().to_vec(), programs, macs, peak_bytes, scratch_bytes })
    }

    /// Exact source graph's validated liveness schedule.
    pub fn memory(&self) -> &MemoryPlan { &self.memory }
    /// Full execution plan identity, including backend implementation and scratch schedule.
    pub fn digest(&self) -> ContentDigest { self.digest }
    /// Kernel/driver/tensor implementation profile, distinct from model weights.
    pub fn profile(&self) -> ContentDigest { self.profile }
    /// Compile-time requirements for tightly backed inputs. Actual views are checked at run time.
    pub fn minimum_requirements(&self) -> ScalarMemoryRequirements {
        ScalarMemoryRequirements { macs: self.macs, peak_bytes: self.peak_bytes,
            scratch_bytes: self.scratch_bytes, input_backing_bytes: self.memory.input_bytes() }
    }

    /// Execute with exact bindings and whole-graph admission BEFORE the first kernel.
    /// The shared backend's results/work are verified at every step. All graph outputs
    /// are returned together; cancellation and late kernel refusal expose no prefix.
    pub fn run<S: AsRef<str>>(&self, inputs: &[(S, Tensor)], budget: PeakExecBudget,
        cx: &ScalarExecCx) -> Result<PlannedExecOutcome, PlannedExecError> {
        cx.checkpoint("planned-scalar:admit")?;
        if inputs.len() != self.inputs.len() { return Err(PlannedExecError::InputSet); }
        let mut bindings = BTreeMap::new();
        for (name, tensor) in inputs {
            if bindings.insert(name.as_ref(), tensor).is_some() { return Err(PlannedExecError::InputSet); }
        }
        let mut extra_backing = 0;
        for port in &self.inputs {
            cx.checkpoint("planned-scalar:input")?;
            let tensor = bindings.get(port.name()).ok_or(PlannedExecError::InputSet)?;
            if tensor.dtype() != port.dtype() || tensor.shape() != port.shape()
                || tensor.generation() != port.generation() { return Err(PlannedExecError::InputContract); }
            // A narrow slice still owns its full backing Arc. Shared storage is counted
            // once per named binding conservatively, never by nondeterministic pointer IDs.
            extra_backing = add(extra_backing, tensor.view().storage().len().saturating_sub(bytes(port)?))?;
        }
        let required = ScalarMemoryRequirements { macs: self.macs,
            peak_bytes: add(self.peak_bytes, extra_backing)?, scratch_bytes: self.scratch_bytes,
            input_backing_bytes: add(self.memory.input_bytes(), extra_backing)? };
        if required.macs > budget.max_macs || required.peak_bytes > budget.max_peak_bytes
            || required.scratch_bytes > budget.max_scratch_bytes {
            return Err(PlannedExecError::BudgetExceeded { required, budget });
        }
        let mut env = BTreeMap::new();
        for port in &self.inputs {
            env.insert(port.name().to_owned(), Tensor::clone(bindings.get(port.name()).copied()
                .ok_or(PlannedExecError::InputSet)?));
        }
        let mut executed_macs = 0_u64;
        let mut peak_live = required.input_backing_bytes;
        let mut released = 0;
        for (program, step) in self.programs.iter().zip(self.memory.steps()) {
            cx.checkpoint("planned-scalar:node")?;
            let args: Vec<_> = program.graph.inputs().iter().map(|p| {
                env.get(p.name()).cloned().map(|t| (p.name(), t)).ok_or(PlannedExecError::BackendMismatch)
            }).collect::<Result<_, _>>()?;
            let result = ScalarExecutor::run(&program.graph, &args,
                ExecBudget::new(program.macs, program.cumulative_bytes), cx)?;
            if result.executed_macs() != program.macs || result.nodes_executed() != 1
                || result.allocated_bytes() != program.cumulative_bytes {
                return Err(PlannedExecError::BackendMismatch);
            }
            executed_macs = executed_macs.checked_add(result.executed_macs()).ok_or(PlannedExecError::Overflow)?;
            let mut output = result.into_outputs();
            if output.len() != program.graph.output_count() { return Err(PlannedExecError::BackendMismatch); }
            for port in program.graph.outputs() {
                let tensor = output.remove(port.name()).ok_or(PlannedExecError::BackendMismatch)?;
                if tensor.dtype() != port.dtype() || tensor.shape() != port.shape()
                    || tensor.generation() != port.generation() { return Err(PlannedExecError::BackendMismatch); }
                if env.insert(port.name().to_owned(), tensor).is_some() { return Err(PlannedExecError::BackendMismatch); }
            }
            // Destroy temporary Arc clones before retiring their environment entries.
            drop(args);
            let live = add(resident_bytes(&env)?, extra_backing)?;
            if live != add(step.live_bytes(), extra_backing)? { return Err(PlannedExecError::BackendMismatch); }
            peak_live = peak_live.max(live);
            for name in step.release_after() {
                if env.remove(name).is_none() { return Err(PlannedExecError::BackendMismatch); }
                released += 1;
            }
            if resident_bytes(&env)? != step.retained_bytes() { return Err(PlannedExecError::BackendMismatch); }
        }
        if executed_macs != self.macs { return Err(PlannedExecError::BackendMismatch); }
        let mut outputs = BTreeMap::new();
        for port in &self.outputs {
            outputs.insert(port.name().to_owned(), env.remove(port.name()).ok_or(PlannedExecError::BackendMismatch)?);
        }
        cx.checkpoint("planned-scalar:publish")?;
        let receipt = ScalarMemoryReceipt { graph: self.memory.graph_digest(), plan: self.digest,
            profile: self.profile, required, peak_live_tensor_bytes: peak_live,
            cumulative_tensor_bytes: self.memory.cumulative_bytes(), released_values: released };
        Ok(PlannedExecOutcome { execution: ExecOutcome::new(outputs, executed_macs,
            self.memory.cumulative_bytes(), self.programs.len()), receipt })
    }
}

impl ScalarExecutor {
    /// Compile a reusable peak-memory execution plan over this executor's kernels.
    pub fn plan_memory(graph: &ModelIrGraph, limits: MemoryPlanLimits, cx: &ScalarExecCx)
        -> Result<CompiledScalarPlan, PlannedExecError> {
        CompiledScalarPlan::compile(graph, limits, cx)
    }

    /// Execute once with explicit peak/scratch bounds instead of the legacy cumulative byte limit.
    /// Reuse `plan_memory` for repeated frames to avoid recompiling graph metadata.
    pub fn run_peak<S: AsRef<str>>(graph: &ModelIrGraph, inputs: &[(S, Tensor)],
        budget: PeakExecBudget, cx: &ScalarExecCx) -> Result<PlannedExecOutcome, PlannedExecError> {
        Self::plan_memory(graph, MemoryPlanLimits::default(), cx)?.run(inputs, budget, cx)
    }
}

/// Resource witness for a completed invocation, not a measured RSS or effect receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScalarMemoryReceipt {
    graph: ContentDigest,
    plan: ContentDigest,
    profile: ContentDigest,
    required: ScalarMemoryRequirements,
    peak_live_tensor_bytes: usize,
    cumulative_tensor_bytes: usize,
    released_values: usize,
}
impl ScalarMemoryReceipt {
    /// Exact graph identity from compilation.
    pub fn graph(&self) -> ContentDigest { self.graph }
    /// Memory/work/backend plan identity.
    pub fn plan(&self) -> ContentDigest { self.plan }
    /// Executed kernel/driver/tensor implementation profile.
    pub fn profile(&self) -> ContentDigest { self.profile }
    /// Admitted whole-invocation payload/work requirements, including actual backing buffers.
    pub fn requirements(&self) -> ScalarMemoryRequirements { self.required }
    /// Verified environment tensor high-water mark; scratch is reserved, not sampled.
    pub fn peak_live_tensor_bytes(&self) -> usize { self.peak_live_tensor_bytes }
    /// Cumulative logical bytes, kept distinct from peak live memory.
    pub fn cumulative_tensor_bytes(&self) -> usize { self.cumulative_tensor_bytes }
    /// Number of intermediate values actually removed at last-use boundaries.
    pub fn released_values(&self) -> usize { self.released_values }
    /// Binds the resource witness; not an input/output-content or custody attestation.
    pub fn digest(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new(); e.text("fss.reference.scalar_memory_receipt.v1");
        for digest in [self.graph, self.plan, self.profile] { e.digest(digest); }
        e.u64(self.required.macs);
        for count in [self.required.peak_bytes, self.required.scratch_bytes, self.required.input_backing_bytes,
            self.peak_live_tensor_bytes, self.cumulative_tensor_bytes, self.released_values] { e.u64(count as u64); }
        ContentDigest::sha256(&e.finish())
    }
}

/// Complete outputs plus their separate peak-memory execution witness.
#[derive(Debug)]
pub struct PlannedExecOutcome {
    execution: ExecOutcome,
    receipt: ScalarMemoryReceipt,
}
impl PlannedExecOutcome {
    /// Ordinary scalar outputs and unchanged cumulative byte/work reporting.
    pub fn execution(&self) -> &ExecOutcome { &self.execution }
    /// Peak/scratch/lifetime witness, deliberately separate from cumulative allocations.
    pub fn receipt(&self) -> &ScalarMemoryReceipt { &self.receipt }
    /// Transfer complete outputs and the resource witness to the caller.
    pub fn into_parts(self) -> (ExecOutcome, ScalarMemoryReceipt) { (self.execution, self.receipt) }
}

fn add(a: usize, b: usize) -> Result<usize, PlannedExecError> {
    a.checked_add(b).ok_or(PlannedExecError::Overflow)
}
fn bytes(port: &TensorPort) -> Result<usize, PlannedExecError> {
    port.shape().size_bytes(port.dtype()).map_err(ExecError::Tensor).map_err(Into::into)
}
fn resident_bytes(env: &BTreeMap<String, Tensor>) -> Result<usize, PlannedExecError> {
    env.values().try_fold(0, |sum, tensor| {
        add(sum, tensor.shape().size_bytes(tensor.dtype()).map_err(ExecError::Tensor)?)
    })
}
fn execution_profile() -> ContentDigest {
    let mut e = CanonicalEncoder::new(); e.text("fss.reference.planned_scalar_profile.v1");
    for source in [include_bytes!("planned_scalar.rs").as_slice(),
        include_bytes!("planned_scalar/budget.rs").as_slice(), include_bytes!("scalar_executor.rs").as_slice(),
        include_bytes!("../../fss-model-ir/src/memory.rs").as_slice(),
        include_bytes!("../../fss-tensor/src/tensor.rs").as_slice(),
        include_bytes!("../../fss-tensor/src/view.rs").as_slice(),
        include_bytes!("../../fss-tensor/src/storage.rs").as_slice(),
        include_bytes!("../../fss-tensor/src/dtype.rs").as_slice(),
        include_bytes!("../../fss-tensor/src/shape.rs").as_slice(),
        include_bytes!("../../fss-tensor/src/stride.rs").as_slice()] {
        e.digest(ContentDigest::sha256(source));
    }
    ContentDigest::sha256(&e.finish())
}

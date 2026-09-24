#![forbid(unsafe_code)]
#![deny(clippy::wildcard_enum_match_arm)]
//! Deterministic scalar reference executor over `fss_model_ir::ModelIrGraph`.
//!
//! Evaluates frozen Model IR v1 graphs over typed `fss_tensor::Tensor` instances with
//! bit-reproducible numerical accumulation, checked resource budgeting, cooperative cancellation,
//! and F32 arithmetic. Exact integer inputs are admitted only as embedding indices.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use fss_core::Generation;
use fss_model_ir::{
    GraphValidator, ModelIrError, ModelIrGraph, ModelIrVersion, OpCode, ProducerId, TensorPort,
    infer_operator_outputs,
};
use fss_tensor::{DType, Shape, Tensor, TensorError};

/// Deterministic scalar single-precision exponential function.
///
/// Uses range reduction ($x = k \ln 2 + r$, with $|r| \le \frac{\ln 2}{2}$)
/// followed by a degree-7 polynomial approximation and exact IEEE 754 power-of-two scaling.
///
/// Guaranteed host-independent and bit-reproducible. Uses only IEEE 754 `+`, `-`, `*`, `/`.
/// Never calls platform math libraries or fused multiply-add (`mul_add`).
/// Maximum relative error across `[-87.0, 88.0]` is less than $1 \times 10^{-7}$.
#[must_use]
pub fn deterministic_exp_f32(x: f32) -> f32 {
    if x.is_nan() {
        return x;
    }
    if x == f32::INFINITY {
        return f32::INFINITY;
    }
    if x == f32::NEG_INFINITY || x < -104.0_f32 {
        return 0.0_f32;
    }
    if x > 88.722_84_f32 {
        return f32::INFINITY;
    }

    let x_f64 = x as f64;
    let inv_ln2 = std::f64::consts::LOG2_E;
    let v = x_f64 * inv_ln2;
    let k = if v >= 0.0 {
        (v + 0.5) as i32
    } else {
        (v - 0.5) as i32
    };

    let ln2_hi = std::f64::consts::LN_2;
    let ln2_lo = 2.3190468138462996e-17_f64;
    let r = (x_f64 - (k as f64) * ln2_hi) - (k as f64) * ln2_lo;

    let c1 = 1.0_f64;
    let c2 = 1.0_f64 / 2.0_f64;
    let c3 = 1.0_f64 / 6.0_f64;
    let c4 = 1.0_f64 / 24.0_f64;
    let c5 = 1.0_f64 / 120.0_f64;
    let c6 = 1.0_f64 / 720.0_f64;
    let c7 = 1.0_f64 / 5040.0_f64;

    let poly = 1.0_f64 + r * (c1 + r * (c2 + r * (c3 + r * (c4 + r * (c5 + r * (c6 + r * c7))))));

    // IEEE 754 power-of-two scaling via exact f64 exponent bias (1023)
    let k_i64 = k as i64;
    let scale_bits = ((k_i64 + 1023) as u64) << 52;
    let scale_f64 = f64::from_bits(scale_bits);

    (poly * scale_f64) as f32
}

/// Deterministic scalar single-precision logistic sigmoid function $\sigma(x) = \frac{1}{1 + e^{-x}}$.
///
/// Employs branching for positive and negative arguments to prevent intermediate overflow,
/// and delegates to [`deterministic_exp_f32`] for cross-platform bit reproducibility.
#[must_use]
pub fn deterministic_sigmoid_f32(x: f32) -> f32 {
    if x.is_nan() {
        return x;
    }
    if x >= 0.0_f32 {
        let e_neg = deterministic_exp_f32(-x);
        1.0_f32 / (1.0_f32 + e_neg)
    } else {
        let e_pos = deterministic_exp_f32(x);
        e_pos / (1.0_f32 + e_pos)
    }
}

/// Cooperative execution and cancellation context for scalar graph evaluation.
#[derive(Debug)]
pub struct ScalarExecCx {
    cancelled: AtomicBool,
    drain_completed: AtomicBool,
}

impl ScalarExecCx {
    /// Constructs a new cancellation-aware context.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            drain_completed: AtomicBool::new(false),
        }
    }

    /// Requests cooperative cancellation of the ongoing execution.
    pub fn request_cancellation(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Returns `true` if cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Completes the drain and finalize lifecycle phase, guaranteeing no partial outputs escape.
    pub fn drain_and_finalize(&self) {
        self.drain_completed.store(true, Ordering::SeqCst);
    }

    /// Returns `true` if the drain/finalize cycle was completed.
    #[must_use]
    pub fn is_drain_completed(&self) -> bool {
        self.drain_completed.load(Ordering::SeqCst)
    }

    /// Checkpoint invoked at stage boundaries. Fails closed with [`ExecError::CancellationRequested`]
    /// if cancellation was requested, completing the drain/finalize cycle.
    pub fn checkpoint(&self, stage: &'static str) -> Result<(), ExecError> {
        if self.is_cancelled() {
            self.drain_and_finalize();
            Err(ExecError::CancellationRequested { stage })
        } else {
            Ok(())
        }
    }
}

impl Default for ScalarExecCx {
    fn default() -> Self {
        Self::new()
    }
}

/// Execution resource budget bounding computational MACs and tensor memory bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecBudget {
    /// Maximum allowed multiply-accumulate operations.
    pub max_macs: u64,
    /// Maximum allowed cumulative tensor buffer allocation bytes.
    pub max_bytes: usize,
}

impl ExecBudget {
    /// Constructs a concrete execution budget.
    #[must_use]
    pub const fn new(max_macs: u64, max_bytes: usize) -> Self {
        Self {
            max_macs,
            max_bytes,
        }
    }

    /// Constructs an unbounded budget for unconstrained testing.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_macs: u64::MAX,
            max_bytes: usize::MAX,
        }
    }
}

/// Detailed execution outcome of a completed scalar graph run.
#[derive(Debug, Clone)]
pub struct ExecOutcome {
    outputs: BTreeMap<String, Tensor>,
    executed_macs: u64,
    allocated_bytes: usize,
    nodes_executed: usize,
}

impl ExecOutcome {
    /// Constructs a new execution outcome.
    #[must_use]
    pub fn new(
        outputs: BTreeMap<String, Tensor>,
        executed_macs: u64,
        allocated_bytes: usize,
        nodes_executed: usize,
    ) -> Self {
        Self {
            outputs,
            executed_macs,
            allocated_bytes,
            nodes_executed,
        }
    }

    /// Returns a reference to the map of output tensors by port name.
    #[must_use]
    pub fn outputs(&self) -> &BTreeMap<String, Tensor> {
        &self.outputs
    }

    /// Retrieves an output tensor by port name.
    #[must_use]
    pub fn get_output(&self, name: &str) -> Option<&Tensor> {
        self.outputs.get(name)
    }

    /// Consumes the outcome, returning the map of output tensors.
    #[must_use]
    pub fn into_outputs(self) -> BTreeMap<String, Tensor> {
        self.outputs
    }

    /// Returns the total multiply-accumulate operations performed.
    #[must_use]
    pub fn executed_macs(&self) -> u64 {
        self.executed_macs
    }

    /// Returns the cumulative tensor allocation size in bytes.
    #[must_use]
    pub fn allocated_bytes(&self) -> usize {
        self.allocated_bytes
    }

    /// Returns the number of computation nodes executed.
    #[must_use]
    pub fn nodes_executed(&self) -> usize {
        self.nodes_executed
    }
}

/// Execution errors emitted by [`ScalarExecutor`].
#[derive(Debug, Clone, PartialEq)]
pub enum ExecError {
    /// Graph validation or shape inference failure from Model IR.
    Ir(ModelIrError),
    /// Tensor manipulation or storage allocation failure.
    Tensor(TensorError),
    /// Model IR version is not supported by this runtime.
    UnsupportedVersion {
        /// Expected version.
        expected: u32,
        /// Actual version found in graph.
        actual: u32,
    },
    /// Encountered an operator not supported by the scalar executor.
    UnsupportedOperator {
        /// Node identifier.
        node_id: String,
        /// Operator opcode.
        op: OpCode,
    },
    /// Tensor data type is not admitted for this port or operator.
    UnsupportedDType {
        /// Expected data type (F32 except for exact embedding-index bindings).
        expected: DType,
        /// Actual data type encountered.
        actual: DType,
        /// Tensor port name.
        tensor_name: String,
    },
    /// A required graph input port was not provided in the input tensor list.
    MissingInputPort {
        /// Expected port name.
        expected_port: String,
    },
    /// Incompatible tensor shapes between declaration and actual input.
    ShapeMismatch {
        /// Node or entity identifier.
        node_id: String,
        /// Operator identifier.
        op_id: &'static str,
        /// Reason for mismatch.
        reason: String,
    },
    /// Input tensor generation does not match the graph generation.
    GenerationMismatch {
        /// Expected generation.
        expected: Generation,
        /// Actual generation.
        actual: Generation,
        /// Tensor port name.
        tensor_name: String,
    },
    /// Execution resource limits exceeded.
    BudgetExceeded {
        /// Calculated or executed MACs.
        macs: u64,
        /// Maximum allowed MACs.
        max_macs: u64,
        /// Calculated or allocated bytes.
        bytes: usize,
        /// Maximum allowed bytes.
        max_bytes: usize,
    },
    /// Cooperative cancellation was requested during execution.
    CancellationRequested {
        /// Stage at which cancellation occurred.
        stage: &'static str,
    },
    /// Integer overflow during execution calculation.
    ArithmeticOverflow {
        /// Operation that caused overflow.
        operation: &'static str,
    },
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ir(err) => write!(f, "Model IR error: {err}"),
            Self::Tensor(err) => write!(f, "Tensor error: {err}"),
            Self::UnsupportedVersion { expected, actual } => {
                write!(
                    f,
                    "Model IR version mismatch: expected v{expected}, got v{actual}"
                )
            }
            Self::UnsupportedOperator { node_id, op } => {
                write!(f, "Unsupported operator {op:?} at node '{node_id}'")
            }
            Self::UnsupportedDType {
                expected,
                actual,
                tensor_name,
            } => {
                write!(
                    f,
                    "Unsupported data type for tensor '{tensor_name}': expected {expected:?}, got {actual:?}"
                )
            }
            Self::MissingInputPort { expected_port } => {
                write!(f, "Missing required graph input port '{expected_port}'")
            }
            Self::ShapeMismatch {
                node_id,
                op_id,
                reason,
            } => {
                write!(f, "Shape mismatch at node '{node_id}' ({op_id}): {reason}")
            }
            Self::GenerationMismatch {
                expected,
                actual,
                tensor_name,
            } => {
                write!(
                    f,
                    "Generation mismatch for tensor '{tensor_name}': expected {expected}, got {actual}"
                )
            }
            Self::BudgetExceeded {
                macs,
                max_macs,
                bytes,
                max_bytes,
            } => {
                write!(
                    f,
                    "Execution budget exceeded: macs={macs}/{max_macs}, bytes={bytes}/{max_bytes}"
                )
            }
            Self::CancellationRequested { stage } => {
                write!(f, "Execution cancelled at stage '{stage}'")
            }
            Self::ArithmeticOverflow { operation } => {
                write!(f, "Arithmetic overflow during: {operation}")
            }
        }
    }
}

impl std::error::Error for ExecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ir(err) => Some(err),
            Self::Tensor(err) => Some(err),
            Self::UnsupportedVersion { .. }
            | Self::UnsupportedOperator { .. }
            | Self::UnsupportedDType { .. }
            | Self::MissingInputPort { .. }
            | Self::ShapeMismatch { .. }
            | Self::GenerationMismatch { .. }
            | Self::BudgetExceeded { .. }
            | Self::CancellationRequested { .. }
            | Self::ArithmeticOverflow { .. } => None,
        }
    }
}

impl From<ModelIrError> for ExecError {
    fn from(err: ModelIrError) -> Self {
        Self::Ir(err)
    }
}

impl From<TensorError> for ExecError {
    fn from(err: TensorError) -> Self {
        Self::Tensor(err)
    }
}

/// Channel transformation mode for preprocessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelTransform {
    /// Preserve 3-channel RGB.
    Rgb,
    /// Convert 3-channel RGB to single-channel luminance (BT.601 coefficients: 0.299 R + 0.587 G + 0.114 B).
    LumaOnly,
}

/// Recorded preprocessing program converting raw decoder frames into model input tensors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreprocessProgram {
    /// Target image height in pixels.
    pub target_height: usize,
    /// Target image width in pixels.
    pub target_width: usize,
    /// Channel transformation mode.
    pub channel_transform: ChannelTransform,
    /// Scale integer values in `[0, 255]` to floating point `[0.0, 1.0]`.
    pub scale_to_unit: bool,
}

impl PreprocessProgram {
    /// Constructs a standard preprocessing program for vision inference.
    #[must_use]
    pub const fn new(
        target_height: usize,
        target_width: usize,
        channel_transform: ChannelTransform,
        scale_to_unit: bool,
    ) -> Self {
        Self {
            target_height,
            target_width,
            channel_transform,
            scale_to_unit,
        }
    }

    /// Serializes canonical program parameters for provenance hashing.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(18);
        buf.extend_from_slice(&(self.target_height as u64).to_be_bytes());
        buf.extend_from_slice(&(self.target_width as u64).to_be_bytes());
        buf.push(match self.channel_transform {
            ChannelTransform::Rgb => 0,
            ChannelTransform::LumaOnly => 1,
        });
        buf.push(if self.scale_to_unit { 1 } else { 0 });
        buf
    }

    /// Executes preprocessing on raw HWC U8 bytes, returning a 4D NCHW F32 tensor ($N=1$).
    pub fn execute_bytes(
        &self,
        bytes: &[u8],
        h: usize,
        w: usize,
        c: usize,
        generation: Generation,
    ) -> Result<Tensor, ExecError> {
        if h != self.target_height || w != self.target_width {
            return Err(ExecError::ShapeMismatch {
                node_id: "preprocess".to_string(),
                op_id: "preprocess_hwc",
                reason: format!(
                    "input dimensions ({h}x{w}) do not match target ({}x{})",
                    self.target_height, self.target_width
                ),
            });
        }
        let expected_len = h.checked_mul(w).and_then(|v| v.checked_mul(c)).ok_or(
            ExecError::ArithmeticOverflow {
                operation: "preprocess buffer size calculation",
            },
        )?;
        if bytes.len() != expected_len {
            return Err(ExecError::ShapeMismatch {
                node_id: "preprocess".to_string(),
                op_id: "preprocess_hwc",
                reason: format!(
                    "buffer length mismatch: expected {expected_len}, got {}",
                    bytes.len()
                ),
            });
        }

        let out_c = match self.channel_transform {
            ChannelTransform::Rgb => {
                if c != 3 {
                    return Err(ExecError::ShapeMismatch {
                        node_id: "preprocess".to_string(),
                        op_id: "preprocess_rgb",
                        reason: format!("RGB transform requires 3 channels, got {c}"),
                    });
                }
                3
            }
            ChannelTransform::LumaOnly => {
                if c != 1 && c != 3 {
                    return Err(ExecError::ShapeMismatch {
                        node_id: "preprocess".to_string(),
                        op_id: "preprocess_luma",
                        reason: format!("Luma transform requires 1 or 3 channels, got {c}"),
                    });
                }
                1
            }
        };

        let total_elems = h.checked_mul(w).and_then(|v| v.checked_mul(out_c)).ok_or(
            ExecError::ArithmeticOverflow {
                operation: "preprocess output element count",
            },
        )?;
        let mut out_values = vec![0.0_f32; total_elems];
        let scale = if self.scale_to_unit {
            1.0_f32 / 255.0_f32
        } else {
            1.0_f32
        };

        match self.channel_transform {
            ChannelTransform::Rgb => {
                for y in 0..h {
                    for x in 0..w {
                        let hwc_base = (y * w + x) * 3;
                        let r = (bytes[hwc_base] as f32) * scale;
                        let g = (bytes[hwc_base + 1] as f32) * scale;
                        let b = (bytes[hwc_base + 2] as f32) * scale;

                        out_values[y * w + x] = r;
                        out_values[h * w + y * w + x] = g;
                        out_values[2 * h * w + y * w + x] = b;
                    }
                }
            }
            ChannelTransform::LumaOnly => {
                for y in 0..h {
                    for x in 0..w {
                        let luma = if c == 3 {
                            let hwc_base = (y * w + x) * 3;
                            let r = bytes[hwc_base] as f32;
                            let g = bytes[hwc_base + 1] as f32;
                            let b = bytes[hwc_base + 2] as f32;
                            (0.299_f32 * r + 0.587_f32 * g + 0.114_f32 * b) * scale
                        } else {
                            (bytes[y * w + x] as f32) * scale
                        };
                        out_values[y * w + x] = luma;
                    }
                }
            }
        }

        let out_shape = Shape::new(vec![1, out_c, h, w])?;
        Tensor::from_values(out_shape, &out_values, generation).map_err(ExecError::Tensor)
    }

    /// Executes preprocessing on a U8 tensor with shape `[H, W, C]`.
    pub fn execute(
        &self,
        input_hwc_u8: &Tensor,
        generation: Generation,
    ) -> Result<Tensor, ExecError> {
        if input_hwc_u8.dtype() != DType::U8 {
            return Err(ExecError::UnsupportedDType {
                expected: DType::U8,
                actual: input_hwc_u8.dtype(),
                tensor_name: "preprocess_input".to_string(),
            });
        }
        let dims = input_hwc_u8.shape().dims();
        if dims.len() != 3 {
            return Err(ExecError::ShapeMismatch {
                node_id: "preprocess".to_string(),
                op_id: "preprocess_hwc",
                reason: format!("expected 3D [H, W, C] tensor, got rank {}", dims.len()),
            });
        }
        let bytes = input_hwc_u8.to_vec::<u8>()?;
        self.execute_bytes(&bytes, dims[0], dims[1], dims[2], generation)
    }
}

/// Helper calculating row-major contiguous strides for a shape slice.
fn compute_row_major_strides(dims: &[usize]) -> Vec<usize> {
    if dims.is_empty() {
        return Vec::new();
    }
    let mut strides: Vec<usize> = vec![1; dims.len()];
    for i in (0..dims.len().saturating_sub(1)).rev() {
        strides[i] = strides[i + 1].saturating_mul(dims[i + 1]);
    }
    strides
}

// Integer data is not an arithmetic widening policy. Every use of an admitted integer
// input must be the indices port of Embedding; unused integers and integer outputs stay
// unsupported. Intermediate outputs are still checked to be F32 during graph preflight.
fn is_embedding_index_input(graph: &ModelIrGraph, input: &TensorPort) -> bool {
    if !input.dtype().is_integer()
        || graph
            .outputs()
            .iter()
            .any(|output| output.name() == input.name())
    {
        return false;
    }
    let mut used = false;
    for node in graph.nodes() {
        for (position, name) in node.inputs().iter().enumerate() {
            if name == input.name() {
                if node.op() != OpCode::Embedding || position != 0 {
                    return false;
                }
                used = true;
            }
        }
    }
    used
}

/// Computes upper-bound multiply-accumulate operations for a single computational node.
pub(crate) fn compute_node_macs(
    node: &fss_model_ir::GraphNode,
    in_ports: &[TensorPort],
    out_ports: &[TensorPort],
) -> Result<u64, ExecError> {
    match node.op() {
        OpCode::Conv2d => {
            if in_ports.len() < 2 || out_ports.is_empty() {
                return Ok(0);
            }
            let out_elems = out_ports[0].shape().num_elements()?;
            let w_dims = in_ports[1].shape().dims();
            let kh = w_dims.get(2).copied().unwrap_or(1);
            let kw = w_dims.get(3).copied().unwrap_or(1);
            let cin_per_group = w_dims.get(1).copied().unwrap_or(1);

            let macs_per_elem = cin_per_group
                .checked_mul(kh)
                .and_then(|v| v.checked_mul(kw))
                .ok_or(ExecError::ArithmeticOverflow {
                    operation: "conv2d macs per element",
                })?;

            let total = (out_elems as u64).checked_mul(macs_per_elem as u64).ok_or(
                ExecError::ArithmeticOverflow {
                    operation: "conv2d total macs",
                },
            )?;
            Ok(total)
        }
        OpCode::MatMul => {
            if in_ports.len() < 2 || out_ports.is_empty() {
                return Ok(0);
            }
            let out_elems = out_ports[0].shape().num_elements()?;
            let in0_dims = in_ports[0].shape().dims();
            let k = in0_dims.last().copied().unwrap_or(1);
            let total =
                (out_elems as u64)
                    .checked_mul(k as u64)
                    .ok_or(ExecError::ArithmeticOverflow {
                        operation: "matmul total macs",
                    })?;
            Ok(total)
        }
        OpCode::MaxPool2d => {
            if out_ports.is_empty() {
                return Ok(0);
            }
            let out_elems = out_ports[0].shape().num_elements()? as u64;
            let (k_h, k_w) = if let Some(a) = node.attributes().get("kernel_size") {
                let ks = a
                    .as_usize_list(node.id(), "kernel_size")
                    .map_err(ExecError::Ir)?;
                let h = ks.first().copied().unwrap_or(1) as u64;
                let w = ks.get(1).copied().unwrap_or(1) as u64;
                (h, w)
            } else {
                (1, 1)
            };
            let window_work = k_h.checked_mul(k_w).ok_or(ExecError::ArithmeticOverflow {
                operation: "maxpool kernel size",
            })?;
            let total =
                out_elems
                    .checked_mul(window_work)
                    .ok_or(ExecError::ArithmeticOverflow {
                        operation: "maxpool total macs",
                    })?;
            Ok(total)
        }
        OpCode::Add
        | OpCode::Sub
        | OpCode::Mul
        | OpCode::Div
        | OpCode::Relu
        | OpCode::Sigmoid
        | OpCode::Softmax => {
            if out_ports.is_empty() {
                return Ok(0);
            }
            let out_elems = out_ports[0].shape().num_elements()? as u64;
            Ok(out_elems)
        }
        OpCode::Transpose | OpCode::Slice => {
            let port = &out_ports[0];
            (port.shape().num_elements()? as u64)
                .checked_mul(port.rank() as u64 + 1)
                .ok_or(ExecError::ArithmeticOverflow {
                    operation: "layout work bound",
                })
        }
        OpCode::Squeeze | OpCode::Unsqueeze | OpCode::Concat => {
            Ok(out_ports[0].shape().num_elements()? as u64)
        }
        OpCode::LayerNorm | OpCode::RMSNorm => normalization_work(node, in_ports, &out_ports[0]),
        OpCode::Gelu | OpCode::Silu | OpCode::Tanh => activation_work(node, &out_ports[0]),
        OpCode::Reshape => Ok(0),
        OpCode::Embedding => {
            // Bound logical index traversal/validation and strided table reads/copies.
            // A zero-width table still requires checking every supplied index.
            let indices = in_ports[0].shape().num_elements()? as u64;
            let elements = out_ports[0].shape().num_elements()? as u64;
            indices
                .checked_mul(2 * in_ports[0].rank() as u64 + 2)
                .and_then(|work| {
                    elements
                        .checked_mul(4)
                        .and_then(|copy| work.checked_add(copy))
                })
                .ok_or(ExecError::ArithmeticOverflow {
                    operation: "embedding work bound",
                })
        }
    }
}

/// Deterministic pure-Rust scalar reference executor over [`ModelIrGraph`].
pub struct ScalarExecutor;

impl ScalarExecutor {
    /// Executes a validated Model IR v1 graph deterministically with scalar math.
    ///
    /// # Errors
    /// Returns [`ExecError`] if graph validation fails, dtypes are unsupported, shapes mismatch,
    /// budget limits are exceeded, cancellation is signaled, or arithmetic overflows occur.
    pub fn run<S: AsRef<str>>(
        graph: &ModelIrGraph,
        inputs: &[(S, Tensor)],
        budget: ExecBudget,
        cx: &ScalarExecCx,
    ) -> Result<ExecOutcome, ExecError> {
        cx.checkpoint("pre-execution")?;

        // 1. Version gate: only ModelIrVersion::V1 (from_u32(1)) is admitted
        let expected_version = ModelIrVersion::from_u32(1).map_err(ExecError::Ir)?;
        if graph.version() != expected_version {
            return Err(ExecError::UnsupportedVersion {
                expected: 1,
                actual: graph.version().as_u32(),
            });
        }

        // 2. Validate graph structure, freeze digest, and acyclic properties
        GraphValidator::validate(graph).map_err(ExecError::Ir)?;

        // 3. Construct canonical ProducerId map identically to canonical.rs
        let mut producer_map = BTreeMap::new();
        for input in graph.inputs() {
            producer_map.insert(input.name(), ProducerId::GraphInput);
        }
        for node in graph.nodes() {
            for out_name in node.outputs() {
                producer_map.insert(out_name.as_str(), ProducerId::Node(node.id()));
            }
        }
        let sorted_nodes =
            GraphValidator::topological_sort(graph, &producer_map).map_err(ExecError::Ir)?;

        // 4. F32 arithmetic, with a narrow exact-integer exception for embedding indices.
        for input in graph.inputs() {
            if input.dtype() != DType::F32 && !is_embedding_index_input(graph, input) {
                return Err(ExecError::UnsupportedDType {
                    expected: DType::F32,
                    actual: input.dtype(),
                    tensor_name: input.name().to_string(),
                });
            }
        }
        for output in graph.outputs() {
            if output.dtype() != DType::F32 {
                return Err(ExecError::UnsupportedDType {
                    expected: DType::F32,
                    actual: output.dtype(),
                    tensor_name: output.name().to_string(),
                });
            }
        }

        // 5. Every frozen opcode has an exhaustive work model and kernel dispatch below.
        // Attribute and dtype support is still checked before any node executes.

        // 6. Bind inputs and verify shapes, dtypes, and generations
        let mut input_map: BTreeMap<&str, &Tensor> = BTreeMap::new();
        for (name, tensor) in inputs {
            if !graph.inputs().iter().any(|i| i.name() == name.as_ref()) {
                return Err(ExecError::ShapeMismatch {
                    node_id: "input".to_string(),
                    op_id: "graph_input",
                    reason: format!("unexpected input port '{}'", name.as_ref()),
                });
            }
            if input_map.insert(name.as_ref(), tensor).is_some() {
                return Err(ExecError::ShapeMismatch {
                    node_id: "input".to_string(),
                    op_id: "graph_input",
                    reason: format!("duplicate input port '{}'", name.as_ref()),
                });
            }
        }

        let mut total_input_bytes: usize = 0;
        let mut env: BTreeMap<String, Tensor> = BTreeMap::new();

        for declared_in in graph.inputs() {
            let provided =
                input_map
                    .get(declared_in.name())
                    .ok_or_else(|| ExecError::MissingInputPort {
                        expected_port: declared_in.name().to_string(),
                    })?;

            if provided.dtype() != declared_in.dtype() {
                return Err(ExecError::UnsupportedDType {
                    expected: declared_in.dtype(),
                    actual: provided.dtype(),
                    tensor_name: declared_in.name().to_string(),
                });
            }

            if provided.shape() != declared_in.shape() {
                return Err(ExecError::ShapeMismatch {
                    node_id: "input".to_string(),
                    op_id: "graph_input",
                    reason: format!(
                        "input port '{}' expected shape {:?}, got {:?}",
                        declared_in.name(),
                        declared_in.shape().dims(),
                        provided.shape().dims()
                    ),
                });
            }

            if provided.generation() != graph.generation() {
                return Err(ExecError::GenerationMismatch {
                    expected: graph.generation(),
                    actual: provided.generation(),
                    tensor_name: declared_in.name().to_string(),
                });
            }

            let tensor_bytes = provided.shape().size_bytes(declared_in.dtype())?;
            total_input_bytes = total_input_bytes.checked_add(tensor_bytes).ok_or(
                ExecError::ArithmeticOverflow {
                    operation: "input tensor bytes accumulation",
                },
            )?;

            env.insert(declared_in.name().to_string(), (*provided).clone());
        }

        // 7. Full graph shape inference, F32 gate, and resource budgeting before execution
        let mut port_env: BTreeMap<String, TensorPort> = BTreeMap::new();
        for input in graph.inputs() {
            port_env.insert(input.name().to_string(), input.clone());
        }

        let mut total_macs: u64 = 0;
        let mut total_output_bytes: usize = 0;
        let mut node_outputs_map: BTreeMap<&str, Vec<TensorPort>> = BTreeMap::new();

        for node in &sorted_nodes {
            let mut in_ports = Vec::with_capacity(node.inputs().len());
            for in_name in node.inputs() {
                let p = port_env
                    .get(in_name)
                    .ok_or_else(|| ExecError::ShapeMismatch {
                        node_id: node.id().to_string(),
                        op_id: node.op().stable_id(),
                        reason: format!("missing intermediate tensor port '{in_name}'"),
                    })?;
                in_ports.push(p.clone());
            }

            let in_port_refs: Vec<&TensorPort> = in_ports.iter().collect();
            let out_ports = infer_operator_outputs(
                node.id(),
                node.op(),
                &in_port_refs,
                node.outputs(),
                node.attributes(),
                graph.generation(),
            )?;

            for out_port in &out_ports {
                if out_port.dtype() != DType::F32 {
                    return Err(ExecError::UnsupportedDType {
                        expected: DType::F32,
                        actual: out_port.dtype(),
                        tensor_name: out_port.name().to_string(),
                    });
                }
                let bytes = out_port.shape().size_bytes(out_port.dtype())?;
                total_output_bytes =
                    total_output_bytes
                        .checked_add(bytes)
                        .ok_or(ExecError::ArithmeticOverflow {
                            operation: "total output bytes accumulation",
                        })?;
                port_env.insert(out_port.name().to_string(), out_port.clone());
            }

            let node_macs = compute_node_macs(node, &in_ports, &out_ports)?;
            total_macs =
                total_macs
                    .checked_add(node_macs)
                    .ok_or(ExecError::ArithmeticOverflow {
                        operation: "total MACs accumulation",
                    })?;

            node_outputs_map.insert(node.id(), out_ports);
        }

        let total_required_bytes = total_input_bytes.checked_add(total_output_bytes).ok_or(
            ExecError::ArithmeticOverflow {
                operation: "total execution bytes accumulation",
            },
        )?;

        if total_macs > budget.max_macs || total_required_bytes > budget.max_bytes {
            return Err(ExecError::BudgetExceeded {
                macs: total_macs,
                max_macs: budget.max_macs,
                bytes: total_required_bytes,
                max_bytes: budget.max_bytes,
            });
        }

        // 8. Execute nodes along canonical topological ordering with cooperative cancellation
        let mut executed_count = 0;

        for node in &sorted_nodes {
            if let Err(err) = cx.checkpoint("node-execution") {
                env.clear();
                return Err(err);
            }

            let mut node_in_tensors = Vec::with_capacity(node.inputs().len());
            for in_name in node.inputs() {
                let t = env.get(in_name).ok_or_else(|| ExecError::ShapeMismatch {
                    node_id: node.id().to_string(),
                    op_id: node.op().stable_id(),
                    reason: format!("tensor '{in_name}' not found in environment"),
                })?;
                node_in_tensors.push(t);
            }

            let out_ports =
                node_outputs_map
                    .get(node.id())
                    .ok_or_else(|| ExecError::ShapeMismatch {
                        node_id: node.id().to_string(),
                        op_id: node.op().stable_id(),
                        reason: "missing cached inferred output ports".to_string(),
                    })?;

            let result_tensor = match node.op() {
                OpCode::Conv2d => {
                    Self::execute_conv2d(node, &node_in_tensors, &out_ports[0], graph.generation())?
                }
                OpCode::Relu => {
                    Self::execute_relu(node_in_tensors[0], &out_ports[0], graph.generation())?
                }
                OpCode::Sigmoid => {
                    Self::execute_sigmoid(node_in_tensors[0], &out_ports[0], graph.generation())?
                }
                OpCode::Add => Self::execute_binary_op(
                    node_in_tensors[0],
                    node_in_tensors[1],
                    &out_ports[0],
                    graph.generation(),
                    |a, b| a + b,
                )?,
                OpCode::Sub => Self::execute_binary_op(
                    node_in_tensors[0],
                    node_in_tensors[1],
                    &out_ports[0],
                    graph.generation(),
                    |a, b| a - b,
                )?,
                OpCode::Mul => Self::execute_binary_op(
                    node_in_tensors[0],
                    node_in_tensors[1],
                    &out_ports[0],
                    graph.generation(),
                    |a, b| a * b,
                )?,
                OpCode::Div => Self::execute_binary_op(
                    node_in_tensors[0],
                    node_in_tensors[1],
                    &out_ports[0],
                    graph.generation(),
                    |a, b| a / b,
                )?,
                OpCode::MaxPool2d => Self::execute_maxpool2d(
                    node,
                    node_in_tensors[0],
                    &out_ports[0],
                    graph.generation(),
                )?,
                OpCode::MatMul => Self::execute_matmul(
                    node_in_tensors[0],
                    node_in_tensors[1],
                    &out_ports[0],
                    graph.generation(),
                )?,
                OpCode::Reshape => {
                    Self::execute_reshape(node_in_tensors[0], &out_ports[0], graph.generation())?
                }
                OpCode::Softmax => Self::execute_softmax(
                    node,
                    node_in_tensors[0],
                    &out_ports[0],
                    graph.generation(),
                )?,
                OpCode::Transpose
                | OpCode::Squeeze
                | OpCode::Unsqueeze
                | OpCode::Concat
                | OpCode::Slice => Self::execute_layout(
                    node,
                    &node_in_tensors,
                    &out_ports[0],
                    graph.generation(),
                    cx,
                )?,
                OpCode::LayerNorm | OpCode::RMSNorm => Self::execute_normalization(
                    node,
                    &node_in_tensors,
                    &out_ports[0],
                    graph.generation(),
                    cx,
                )?,
                OpCode::Gelu | OpCode::Silu | OpCode::Tanh => Self::execute_activation(
                    node,
                    node_in_tensors[0],
                    &out_ports[0],
                    graph.generation(),
                    cx,
                )?,
                OpCode::Embedding => Self::execute_embedding(
                    node,
                    node_in_tensors[0],
                    node_in_tensors[1],
                    &out_ports[0],
                    graph.generation(),
                    cx,
                )?,
            };

            cx.checkpoint("post-node-execution")?;
            env.insert(out_ports[0].name().to_string(), result_tensor);
            executed_count += 1;
        }

        // 9. Collect final declared graph outputs
        let mut final_outputs = BTreeMap::new();
        for declared_out in graph.outputs() {
            let t = env
                .get(declared_out.name())
                .ok_or_else(|| ExecError::ShapeMismatch {
                    node_id: "output".to_string(),
                    op_id: "graph_output",
                    reason: format!(
                        "declared output tensor '{}' was not generated",
                        declared_out.name()
                    ),
                })?;
            final_outputs.insert(declared_out.name().to_string(), t.clone());
        }

        cx.checkpoint("publish-outputs")?;
        Ok(ExecOutcome::new(
            final_outputs,
            total_macs,
            total_required_bytes,
            executed_count,
        ))
    }

    fn execute_conv2d(
        node: &fss_model_ir::GraphNode,
        inputs: &[&Tensor],
        out_port: &TensorPort,
        generation: Generation,
    ) -> Result<Tensor, ExecError> {
        let x = inputs[0];
        let w = inputs[1];
        let b_opt = if inputs.len() >= 3 {
            Some(inputs[2])
        } else {
            None
        };

        let strides = if let Some(a) = node.attributes().get("strides") {
            a.as_usize_list(node.id(), "strides")
                .map_err(ExecError::Ir)?
        } else {
            vec![1, 1]
        };
        let stride_h = strides.first().copied().unwrap_or(1);
        let stride_w = strides.get(1).copied().unwrap_or(1);

        let padding = if let Some(a) = node.attributes().get("padding") {
            a.as_usize_list(node.id(), "padding")
                .map_err(ExecError::Ir)?
        } else {
            vec![0, 0, 0, 0]
        };
        let pad_top = padding.first().copied().unwrap_or(0);
        let pad_left = padding.get(1).copied().unwrap_or(0);

        let dilations = if let Some(a) = node.attributes().get("dilations") {
            a.as_usize_list(node.id(), "dilations")
                .map_err(ExecError::Ir)?
        } else {
            vec![1, 1]
        };
        let dilation_h = dilations.first().copied().unwrap_or(1);
        let dilation_w = dilations.get(1).copied().unwrap_or(1);

        let groups = if let Some(a) = node.attributes().get("groups") {
            a.as_usize(node.id(), "groups").map_err(ExecError::Ir)?
        } else {
            1
        };
        let groups = groups.max(1);

        let x_dims = x.shape().dims();
        let w_dims = w.shape().dims();
        let out_dims = out_port.shape().dims();

        let n_batch = x_dims[0];
        let c_in = x_dims[1];
        let h_in = x_dims[2];
        let w_in = x_dims[3];

        let c_out = out_dims[1];
        let h_out = out_dims[2];
        let w_out = out_dims[3];

        let k_h = w_dims[2];
        let k_w = w_dims[3];

        let c_per_g_out = (c_out / groups).max(1);
        let c_per_g_in = (c_in / groups).max(1);

        let x_vec = x.to_vec::<f32>()?;
        let w_vec = w.to_vec::<f32>()?;
        let b_vec = if let Some(b) = b_opt {
            Some(b.to_vec::<f32>()?)
        } else {
            None
        };

        let total_elems = out_port.shape().num_elements()?;
        let mut out_vec = Vec::with_capacity(total_elems);

        for n in 0..n_batch {
            for cout in 0..c_out {
                let g = cout / c_per_g_out;
                let cin_start = g * c_per_g_in;
                let bias_val = if let Some(ref b) = b_vec {
                    b.get(cout).copied().unwrap_or(0.0_f32)
                } else {
                    0.0_f32
                };

                for oh in 0..h_out {
                    for ow in 0..w_out {
                        let mut acc = 0.0_f32;

                        for cin_g in 0..c_per_g_in {
                            let cin = cin_start + cin_g;
                            for kh in 0..k_h {
                                let in_h_pos = match (oh.checked_mul(stride_h))
                                    .and_then(|s| s.checked_add(kh.checked_mul(dilation_h)?))
                                {
                                    Some(pos) => pos,
                                    None => continue,
                                };
                                if in_h_pos < pad_top {
                                    continue;
                                }
                                let ih_u = in_h_pos - pad_top;
                                if ih_u >= h_in {
                                    continue;
                                }

                                for kw in 0..k_w {
                                    let in_w_pos = match (ow.checked_mul(stride_w))
                                        .and_then(|s| s.checked_add(kw.checked_mul(dilation_w)?))
                                    {
                                        Some(pos) => pos,
                                        None => continue,
                                    };
                                    if in_w_pos < pad_left {
                                        continue;
                                    }
                                    let iw_u = in_w_pos - pad_left;
                                    if iw_u >= w_in {
                                        continue;
                                    }

                                    let x_idx = ((n * c_in + cin) * h_in + ih_u) * w_in + iw_u;
                                    let w_idx = ((cout * c_per_g_in + cin_g) * k_h + kh) * k_w + kw;

                                    acc += x_vec[x_idx] * w_vec[w_idx];
                                }
                            }
                        }

                        out_vec.push(acc + bias_val);
                    }
                }
            }
        }

        Tensor::from_values(out_port.shape().clone(), &out_vec, generation)
            .map_err(ExecError::Tensor)
    }

    fn execute_relu(
        x: &Tensor,
        out_port: &TensorPort,
        generation: Generation,
    ) -> Result<Tensor, ExecError> {
        let x_vec = x.to_vec::<f32>()?;
        let out_vec: Vec<f32> = x_vec
            .into_iter()
            .map(|v| if v > 0.0_f32 { v } else { 0.0_f32 })
            .collect();
        Tensor::from_values(out_port.shape().clone(), &out_vec, generation)
            .map_err(ExecError::Tensor)
    }

    fn execute_sigmoid(
        x: &Tensor,
        out_port: &TensorPort,
        generation: Generation,
    ) -> Result<Tensor, ExecError> {
        let x_vec = x.to_vec::<f32>()?;
        let out_vec: Vec<f32> = x_vec.into_iter().map(deterministic_sigmoid_f32).collect();
        Tensor::from_values(out_port.shape().clone(), &out_vec, generation)
            .map_err(ExecError::Tensor)
    }

    fn execute_binary_op(
        a: &Tensor,
        b: &Tensor,
        out_port: &TensorPort,
        generation: Generation,
        op_fn: impl Fn(f32, f32) -> f32,
    ) -> Result<Tensor, ExecError> {
        let out_dims = out_port.shape().dims();
        let r_out = out_dims.len();
        let total_elems = out_port.shape().num_elements()?;

        let a_dims = a.shape().dims();
        let b_dims = b.shape().dims();
        let r_a = a_dims.len();
        let r_b = b_dims.len();

        let strides_a = compute_row_major_strides(a_dims);
        let strides_b = compute_row_major_strides(b_dims);

        let mut eff_stride_a = vec![0; r_out];
        let mut eff_stride_b = vec![0; r_out];

        for i in 0..r_out {
            let j = r_out - 1 - i;
            if j < r_a && a_dims[r_a - 1 - j] > 1 {
                eff_stride_a[i] = strides_a[r_a - 1 - j];
            }
            if j < r_b && b_dims[r_b - 1 - j] > 1 {
                eff_stride_b[i] = strides_b[r_b - 1 - j];
            }
        }

        let a_vec = a.to_vec::<f32>()?;
        let b_vec = b.to_vec::<f32>()?;
        let mut out_vec = Vec::with_capacity(total_elems);
        let mut coords = vec![0; r_out];

        for _ in 0..total_elems {
            let mut off_a = 0;
            let mut off_b = 0;
            for k in 0..r_out {
                off_a += coords[k] * eff_stride_a[k];
                off_b += coords[k] * eff_stride_b[k];
            }

            let val_a = a_vec.get(off_a).copied().unwrap_or(0.0_f32);
            let val_b = b_vec.get(off_b).copied().unwrap_or(0.0_f32);
            out_vec.push(op_fn(val_a, val_b));

            for k in (0..r_out).rev() {
                coords[k] += 1;
                if coords[k] < out_dims[k] {
                    break;
                }
                coords[k] = 0;
            }
        }

        Tensor::from_values(out_port.shape().clone(), &out_vec, generation)
            .map_err(ExecError::Tensor)
    }

    fn execute_maxpool2d(
        node: &fss_model_ir::GraphNode,
        x: &Tensor,
        out_port: &TensorPort,
        generation: Generation,
    ) -> Result<Tensor, ExecError> {
        let kernel_size = if let Some(a) = node.attributes().get("kernel_size") {
            a.as_usize_list(node.id(), "kernel_size")
                .map_err(ExecError::Ir)?
        } else {
            return Err(ExecError::ShapeMismatch {
                node_id: node.id().to_string(),
                op_id: "OP-MAXPOOL2D-001",
                reason: "missing mandatory attribute 'kernel_size'".to_string(),
            });
        };
        let k_h = kernel_size.first().copied().unwrap_or(1);
        let k_w = kernel_size.get(1).copied().unwrap_or(1);

        let strides = if let Some(a) = node.attributes().get("strides") {
            a.as_usize_list(node.id(), "strides")
                .map_err(ExecError::Ir)?
        } else {
            vec![1, 1]
        };
        let stride_h = strides.first().copied().unwrap_or(1);
        let stride_w = strides.get(1).copied().unwrap_or(1);

        let padding = if let Some(a) = node.attributes().get("padding") {
            a.as_usize_list(node.id(), "padding")
                .map_err(ExecError::Ir)?
        } else {
            vec![0, 0, 0, 0]
        };
        let pad_top = padding.first().copied().unwrap_or(0);
        let pad_left = padding.get(1).copied().unwrap_or(0);

        let x_dims = x.shape().dims();
        let out_dims = out_port.shape().dims();

        let n_batch = x_dims[0];
        let c_in = x_dims[1];
        let h_in = x_dims[2];
        let w_in = x_dims[3];

        let h_out = out_dims[2];
        let w_out = out_dims[3];

        let x_vec = x.to_vec::<f32>()?;
        let total_elems = out_port.shape().num_elements()?;
        let mut out_vec = Vec::with_capacity(total_elems);

        for n in 0..n_batch {
            for ch in 0..c_in {
                for oh in 0..h_out {
                    for ow in 0..w_out {
                        let mut max_val = f32::NEG_INFINITY;
                        let mut found = false;

                        for kh in 0..k_h {
                            let in_h_pos =
                                match (oh.checked_mul(stride_h)).and_then(|s| s.checked_add(kh)) {
                                    Some(pos) => pos,
                                    None => continue,
                                };
                            if in_h_pos < pad_top {
                                continue;
                            }
                            let ih_u = in_h_pos - pad_top;
                            if ih_u >= h_in {
                                continue;
                            }

                            for kw in 0..k_w {
                                let in_w_pos = match (ow.checked_mul(stride_w))
                                    .and_then(|s| s.checked_add(kw))
                                {
                                    Some(pos) => pos,
                                    None => continue,
                                };
                                if in_w_pos < pad_left {
                                    continue;
                                }
                                let iw_u = in_w_pos - pad_left;
                                if iw_u >= w_in {
                                    continue;
                                }

                                let idx = ((n * c_in + ch) * h_in + ih_u) * w_in + iw_u;
                                let v = x_vec[idx];
                                if !found || v > max_val {
                                    max_val = v;
                                    found = true;
                                }
                            }
                        }

                        out_vec.push(if found { max_val } else { 0.0_f32 });
                    }
                }
            }
        }

        Tensor::from_values(out_port.shape().clone(), &out_vec, generation)
            .map_err(ExecError::Tensor)
    }

    fn execute_matmul(
        a: &Tensor,
        b: &Tensor,
        out_port: &TensorPort,
        generation: Generation,
    ) -> Result<Tensor, ExecError> {
        let out_dims = out_port.shape().dims();
        let r_out = out_dims.len();
        let a_dims = a.shape().dims();
        let b_dims = b.shape().dims();
        let r_a = a_dims.len();
        let r_b = b_dims.len();

        if r_a < 2 || r_b < 2 || r_out < 2 {
            return Err(ExecError::ShapeMismatch {
                node_id: "matmul".to_string(),
                op_id: "OP-MATMUL-001",
                reason: "MatMul requires operands with rank >= 2".to_string(),
            });
        }

        let m = a_dims[r_a - 2];
        let k_dim = a_dims[r_a - 1];
        let n = b_dims[r_b - 1];

        let batch_a = &a_dims[..r_a - 2];
        let batch_b = &b_dims[..r_b - 2];
        let batch_out = &out_dims[..r_out - 2];
        let r_batch = batch_out.len();

        let strides_ba = compute_row_major_strides(batch_a);
        let strides_bb = compute_row_major_strides(batch_b);

        let mut eff_stride_ba = vec![0; r_batch];
        let mut eff_stride_bb = vec![0; r_batch];

        for i in 0..r_batch {
            let j = r_batch - 1 - i;
            if j < batch_a.len() && batch_a[batch_a.len() - 1 - j] > 1 {
                eff_stride_ba[i] = strides_ba[batch_a.len() - 1 - j];
            }
            if j < batch_b.len() && batch_b[batch_b.len() - 1 - j] > 1 {
                eff_stride_bb[i] = strides_bb[batch_b.len() - 1 - j];
            }
        }

        let mut total_batch: usize = 1;
        for &d in batch_out {
            total_batch = total_batch.saturating_mul(d);
        }

        let a_vec = a.to_vec::<f32>()?;
        let b_vec = b.to_vec::<f32>()?;

        let total_elems = out_port.shape().num_elements()?;
        let mut out_vec = Vec::with_capacity(total_elems);
        let mut coords_b = vec![0; r_batch];

        let matrix_a_size = m.saturating_mul(k_dim);
        let matrix_b_size = k_dim.saturating_mul(n);

        for _ in 0..total_batch {
            let mut off_ba_batch = 0;
            let mut off_bb_batch = 0;
            for k in 0..r_batch {
                off_ba_batch += coords_b[k] * eff_stride_ba[k];
                off_bb_batch += coords_b[k] * eff_stride_bb[k];
            }
            let base_a = off_ba_batch * matrix_a_size;
            let base_b = off_bb_batch * matrix_b_size;

            for mi in 0..m {
                for ni in 0..n {
                    let mut acc = 0.0_f32;
                    for ki in 0..k_dim {
                        let idx_a = base_a + mi * k_dim + ki;
                        let idx_b = base_b + ki * n + ni;
                        let val_a = a_vec.get(idx_a).copied().unwrap_or(0.0_f32);
                        let val_b = b_vec.get(idx_b).copied().unwrap_or(0.0_f32);
                        acc += val_a * val_b;
                    }
                    out_vec.push(acc);
                }
            }

            for k in (0..r_batch).rev() {
                coords_b[k] += 1;
                if coords_b[k] < batch_out[k] {
                    break;
                }
                coords_b[k] = 0;
            }
        }

        Tensor::from_values(out_port.shape().clone(), &out_vec, generation)
            .map_err(ExecError::Tensor)
    }

    fn execute_reshape(
        x: &Tensor,
        out_port: &TensorPort,
        generation: Generation,
    ) -> Result<Tensor, ExecError> {
        let x_vec = x.to_vec::<f32>()?;
        Tensor::from_values(out_port.shape().clone(), &x_vec, generation).map_err(ExecError::Tensor)
    }

    fn execute_softmax(
        node: &fss_model_ir::GraphNode,
        x: &Tensor,
        out_port: &TensorPort,
        generation: Generation,
    ) -> Result<Tensor, ExecError> {
        let out_dims = out_port.shape().dims();
        let rank = out_dims.len();
        if rank == 0 {
            return Err(ExecError::ShapeMismatch {
                node_id: node.id().to_string(),
                op_id: "OP-SOFTMAX-001",
                reason: "Softmax requires tensor with rank >= 1".to_string(),
            });
        }

        let axis_raw = if let Some(a) = node.attributes().get("axis") {
            a.as_int(node.id(), "axis").map_err(ExecError::Ir)?
        } else {
            -1
        };

        let axis_idx = if axis_raw < 0 {
            let pos = (rank as i64) + axis_raw;
            if pos < 0 { 0 } else { pos as usize }
        } else {
            (axis_raw as usize).min(rank.saturating_sub(1))
        };

        let d_len = out_dims[axis_idx];
        let mut o_len: usize = 1;
        for &d in &out_dims[..axis_idx] {
            o_len = o_len.saturating_mul(d);
        }
        let mut i_len: usize = 1;
        for &d in &out_dims[axis_idx + 1..] {
            i_len = i_len.saturating_mul(d);
        }

        let x_vec = x.to_vec::<f32>()?;
        let mut out_vec = vec![0.0_f32; x_vec.len()];
        let mut exp_buf = vec![0.0_f32; d_len];

        for o in 0..o_len {
            for i in 0..i_len {
                let mut max_val = f32::NEG_INFINITY;
                for d in 0..d_len {
                    let idx = (o * d_len + d) * i_len + i;
                    let v = x_vec[idx];
                    if v > max_val {
                        max_val = v;
                    }
                }

                let mut sum_exp = 0.0_f32;
                for (d, slot) in exp_buf.iter_mut().enumerate() {
                    let idx = (o * d_len + d) * i_len + i;
                    let e = deterministic_exp_f32(x_vec[idx] - max_val);
                    *slot = e;
                    sum_exp += e;
                }

                let inv_sum = if sum_exp != 0.0_f32 {
                    1.0_f32 / sum_exp
                } else {
                    0.0_f32
                };
                for (d, &e) in exp_buf.iter().enumerate() {
                    let idx = (o * d_len + d) * i_len + i;
                    out_vec[idx] = e * inv_sum;
                }
            }
        }

        Tensor::from_values(out_port.shape().clone(), &out_vec, generation)
            .map_err(ExecError::Tensor)
    }
}

// Layout kernels consume the shape already checked by the frozen Model IR validator.
// Empty outputs short-circuit before stride construction: zero-sized tensors can have
// very large other dimensions without requiring data or overflowing a stride product.
impl ScalarExecutor {
    fn execute_layout(
        node: &fss_model_ir::GraphNode,
        inputs: &[&Tensor],
        output: &TensorPort,
        generation: Generation,
        cx: &ScalarExecCx,
    ) -> Result<Tensor, ExecError> {
        cx.checkpoint("layout:begin")?;
        let count = output.shape().num_elements()?;
        if count == 0 {
            return Tensor::from_values(output.shape().clone(), &[] as &[f32], generation)
                .map_err(ExecError::Tensor);
        }
        let mut values = Vec::with_capacity(count);
        match node.op() {
            OpCode::Squeeze | OpCode::Unsqueeze => {
                let input = inputs[0].to_vec::<f32>()?;
                for chunk in input.chunks(1024) {
                    cx.checkpoint("layout:copy")?;
                    values.extend_from_slice(chunk);
                }
            }
            OpCode::Transpose | OpCode::Slice => {
                let input = inputs[0].to_vec::<f32>()?;
                let dims = inputs[0].shape().dims();
                let strides = layout_strides(dims)?;
                let rank = dims.len();
                let mut axes: Vec<usize> = (0..rank).collect();
                let mut starts = vec![0_usize; rank];
                let mut steps = vec![1_usize; rank];
                if node.op() == OpCode::Transpose {
                    axes = match node.attributes().get("permutation") {
                        Some(value) => value.as_usize_list(node.id(), "permutation")?,
                        None => (0..rank).rev().collect(),
                    };
                } else {
                    let selected_starts = layout_attribute(node, "starts")?;
                    let selected_axes = match node.attributes().get("axes") {
                        Some(value) => value.as_usize_list(node.id(), "axes")?,
                        None => (0..selected_starts.len()).collect(),
                    };
                    let selected_steps = match node.attributes().get("steps") {
                        Some(value) => value.as_usize_list(node.id(), "steps")?,
                        None => vec![1; selected_starts.len()],
                    };
                    for (index, &axis) in selected_axes.iter().enumerate() {
                        starts[axis] = selected_starts[index];
                        steps[axis] = selected_steps[index];
                    }
                }
                let out_dims = output.shape().dims();
                for flat in 0..count {
                    if flat % 1024 == 0 {
                        cx.checkpoint("layout:gather")?;
                    }
                    let mut remainder = flat;
                    let mut offset = 0_usize;
                    for axis in (0..out_dims.len()).rev() {
                        let coordinate = remainder % out_dims[axis];
                        remainder /= out_dims[axis];
                        let source_axis = axes[axis];
                        // Multiply coordinates, not whole strides, by slice steps. A huge
                        // step is valid for a singleton output and must not overflow early.
                        let position = coordinate
                            .checked_mul(steps[source_axis])
                            .and_then(|v| v.checked_add(starts[source_axis]))
                            .and_then(|v| v.checked_mul(strides[source_axis]))
                            .ok_or(ExecError::ArithmeticOverflow {
                                operation: "layout source offset",
                            })?;
                        offset =
                            offset
                                .checked_add(position)
                                .ok_or(ExecError::ArithmeticOverflow {
                                    operation: "layout offset sum",
                                })?;
                    }
                    values.push(
                        *input
                            .get(offset)
                            .ok_or_else(|| layout_mismatch(node, "source offset outside tensor"))?,
                    );
                }
            }
            OpCode::Concat => {
                let rank = output.rank();
                let raw = match node.attributes().get("axis") {
                    Some(value) => value.as_int(node.id(), "axis")?,
                    None => 0,
                };
                let axis = usize::try_from(if raw < 0 { rank as i64 + raw } else { raw })
                    .map_err(|_| layout_mismatch(node, "invalid concatenation axis"))?;
                let dims = output.shape().dims();
                let outer = layout_product(&dims[..axis])?;
                let inner = layout_product(&dims[axis + 1..])?;
                let mut sources = Vec::with_capacity(inputs.len());
                for input in inputs {
                    cx.checkpoint("layout:concat-input")?;
                    let block = input.shape().dims()[axis].checked_mul(inner).ok_or(
                        ExecError::ArithmeticOverflow {
                            operation: "concat block size",
                        },
                    )?;
                    sources.push((input.to_vec::<f32>()?, block));
                }
                for row in 0..outer {
                    cx.checkpoint("layout:concat-row")?;
                    for (source, block) in &sources {
                        let start =
                            row.checked_mul(*block)
                                .ok_or(ExecError::ArithmeticOverflow {
                                    operation: "concat block offset",
                                })?;
                        let end =
                            start
                                .checked_add(*block)
                                .ok_or(ExecError::ArithmeticOverflow {
                                    operation: "concat block end",
                                })?;
                        let slice = source
                            .get(start..end)
                            .ok_or_else(|| layout_mismatch(node, "concat block outside tensor"))?;
                        for chunk in slice.chunks(1024) {
                            cx.checkpoint("layout:concat-copy")?;
                            values.extend_from_slice(chunk);
                        }
                    }
                }
            }
            OpCode::Add
            | OpCode::Sub
            | OpCode::Mul
            | OpCode::Div
            | OpCode::Relu
            | OpCode::Gelu
            | OpCode::Silu
            | OpCode::Sigmoid
            | OpCode::Tanh
            | OpCode::MatMul
            | OpCode::Reshape
            | OpCode::LayerNorm
            | OpCode::RMSNorm
            | OpCode::Softmax
            | OpCode::Conv2d
            | OpCode::MaxPool2d
            | OpCode::Embedding => {
                return Err(ExecError::UnsupportedOperator {
                    node_id: node.id().to_owned(),
                    op: node.op(),
                });
            }
        }
        if values.len() != count {
            return Err(layout_mismatch(node, "output element count mismatch"));
        }
        cx.checkpoint("layout:publish")?;
        Tensor::from_values(output.shape().clone(), &values, generation).map_err(ExecError::Tensor)
    }
}

fn layout_attribute(node: &fss_model_ir::GraphNode, name: &str) -> Result<Vec<usize>, ExecError> {
    node.attributes()
        .get(name)
        .ok_or_else(|| {
            ExecError::Ir(ModelIrError::MissingAttribute {
                node_id: node.id().to_owned(),
                attr_name: name.to_owned(),
            })
        })?
        .as_usize_list(node.id(), name)
        .map_err(ExecError::Ir)
}

fn layout_mismatch(node: &fss_model_ir::GraphNode, reason: &str) -> ExecError {
    ExecError::ShapeMismatch {
        node_id: node.id().to_owned(),
        op_id: node.op().stable_id(),
        reason: reason.to_owned(),
    }
}

fn layout_product(dims: &[usize]) -> Result<usize, ExecError> {
    dims.iter().try_fold(1_usize, |product, &dim| {
        product
            .checked_mul(dim)
            .ok_or(ExecError::ArithmeticOverflow {
                operation: "layout dimension product",
            })
    })
}

fn layout_strides(dims: &[usize]) -> Result<Vec<usize>, ExecError> {
    let mut strides = vec![1_usize; dims.len()];
    for axis in (0..dims.len().saturating_sub(1)).rev() {
        strides[axis] =
            strides[axis + 1]
                .checked_mul(dims[axis + 1])
                .ok_or(ExecError::ArithmeticOverflow {
                    operation: "layout stride product",
                })?;
    }
    Ok(strides)
}

// Frozen v1 normalization: trailing dimensions, population variance, epsilon inside
// the square root, and optional per-element weight/bias. Statistics and affine math
// use ordered binary64 operations; only the final value is rounded to binary32.
// sqrt is the IEEE-754 correctly rounded primitive, not a host transcendental.
fn normalization_width(
    node: &fss_model_ir::GraphNode,
    input_dims: &[usize],
    weight_dims: Option<&[usize]>,
) -> Result<usize, ExecError> {
    let dims = match node.attributes().get("normalized_shape") {
        Some(fss_model_ir::AttrValue::Shape(shape)) => shape.dims().to_vec(),
        Some(value) => value.as_usize_list(node.id(), "normalized_shape")?,
        None => match weight_dims {
            Some(dims) => dims.to_vec(),
            None => input_dims.last().copied().into_iter().collect(),
        },
    };
    let width = layout_product(&dims)?;
    if dims.is_empty() || width == 0 || !input_dims.ends_with(&dims) {
        return Err(layout_mismatch(
            node,
            "invalid trailing normalization dimensions",
        ));
    }
    Ok(width)
}

fn normalization_work(
    node: &fss_model_ir::GraphNode,
    inputs: &[TensorPort],
    output: &TensorPort,
) -> Result<u64, ExecError> {
    let count = output.shape().num_elements()?;
    // Empty tensors do not construct products over their other, potentially huge axes.
    if count == 0 {
        return Ok(0);
    }
    let width = normalization_width(
        node,
        inputs[0].shape().dims(),
        inputs.get(1).map(|port| port.shape().dims()),
    )?;
    (count as u64)
        .checked_mul(8)
        .and_then(|work| {
            (count as u64 / width as u64)
                .checked_mul(4)
                .and_then(|rows| work.checked_add(rows))
        })
        .ok_or(ExecError::ArithmeticOverflow {
            operation: "normalization work bound",
        })
}

impl ScalarExecutor {
    fn execute_normalization(
        node: &fss_model_ir::GraphNode,
        inputs: &[&Tensor],
        output: &TensorPort,
        generation: Generation,
        cx: &ScalarExecCx,
    ) -> Result<Tensor, ExecError> {
        cx.checkpoint("normalization:begin")?;
        let count = output.shape().num_elements()?;
        if count == 0 {
            return Tensor::from_values(output.shape().clone(), &[] as &[f32], generation)
                .map_err(ExecError::Tensor);
        }
        let width = normalization_width(
            node,
            inputs[0].shape().dims(),
            inputs.get(1).map(|tensor| tensor.shape().dims()),
        )?;
        let epsilon = match node.attributes().get("epsilon") {
            Some(value) => value.as_float(node.id(), "epsilon")?,
            None => 1e-5_f64,
        };
        let centered = node.op() == OpCode::LayerNorm;
        let source = inputs[0].to_vec::<f32>()?;
        let weight = inputs
            .get(1)
            .map(|tensor| tensor.to_vec::<f32>())
            .transpose()?;
        let bias = inputs
            .get(2)
            .map(|tensor| tensor.to_vec::<f32>())
            .transpose()?;
        let mut values = Vec::with_capacity(count);
        for row in source.chunks(width) {
            let mut sum = 0.0_f64;
            let mut finite = true;
            for (index, &value) in row.iter().enumerate() {
                if index % 1024 == 0 {
                    cx.checkpoint("normalization:mean")?;
                }
                finite &= value.is_finite();
                sum += f64::from(value);
            }
            // One nonfinite sample makes the complete reduction row undefined. Canonical
            // NaN bits avoid platform-dependent payload propagation; other rows are independent.
            if !finite {
                for index in 0..width {
                    if index % 1024 == 0 {
                        cx.checkpoint("normalization:nonfinite")?;
                    }
                    values.push(f32::from_bits(0x7fc0_0000));
                }
                continue;
            }
            let mean = if centered { sum / width as f64 } else { 0.0 };
            let mut squares = 0.0_f64;
            for (index, &value) in row.iter().enumerate() {
                if index % 1024 == 0 {
                    cx.checkpoint("normalization:variance")?;
                }
                let deviation = f64::from(value) - mean;
                squares += deviation * deviation;
            }
            let divisor = (squares / width as f64 + epsilon).sqrt();
            for (index, &value) in row.iter().enumerate() {
                if index % 1024 == 0 {
                    cx.checkpoint("normalization:affine")?;
                }
                let mut normalized = (f64::from(value) - mean) / divisor;
                if let Some(weight) = &weight {
                    normalized *= f64::from(weight[index]);
                }
                if let Some(bias) = &bias {
                    normalized += f64::from(bias[index]);
                }
                values.push(if normalized.is_nan() {
                    f32::from_bits(0x7fc0_0000)
                } else {
                    normalized as f32
                });
            }
        }
        cx.checkpoint("normalization:publish")?;
        Tensor::from_values(output.shape().clone(), &values, generation).map_err(ExecError::Tensor)
    }
}

// Numeric policy for the three frozen nonlinear activation operators. Evaluate in
// binary64 with bounded series/continued fractions and round once to binary32.
// These are scalar reference algorithms, not calls into host exp/tanh/erf libraries.
fn activation_exp_negative(x: f64) -> f64 {
    // Callers supply x <= 0. Values below this cutoff cannot contribute to any
    // representable binary32 activation, even after multiplication by a finite F32.
    if x < -700.0 {
        return 0.0;
    }
    let k = (x * std::f64::consts::LOG2_E - 0.5) as i32;
    let r = x - f64::from(k) * std::f64::consts::LN_2;
    let mut term = 1.0_f64;
    let mut sum = 1.0_f64;
    for n in 1..=16 {
        term = term * r / f64::from(n);
        sum += term;
    }
    sum * f64::from_bits(((k + 1023) as u64) << 52)
}

fn activation_normal_tail(a: f64) -> f64 {
    const INV_SQRT_TWO_PI: f64 = 0.3989422804014327;
    if a <= 1.0 {
        // Integrate the normal density's power series about zero. This region
        // avoids cancellation; Q(1) remains greater than 0.15.
        let mut term = a;
        let mut integral = a;
        for n in 1..=20 {
            term = term * (-a * a) / (2.0 * f64::from(n));
            integral += term / f64::from(2 * n + 1);
        }
        0.5 - INV_SQRT_TWO_PI * integral
    } else {
        // Laplace continued fraction for Q(a)/phi(a); a > 1. Fixed depth
        // bounds work, and direct tail evaluation preserves small negative GELU.
        let mut remainder = 0.0_f64;
        for n in (1..=256).rev() {
            remainder = f64::from(n) / (a + remainder);
        }
        INV_SQRT_TWO_PI * activation_exp_negative(-0.5 * a * a) / (a + remainder)
    }
}

pub(crate) fn activation_silu(x: f32) -> f32 {
    if x.is_nan() || x == f32::NEG_INFINITY {
        return f32::from_bits(0x7fc0_0000);
    }
    if x == f32::INFINITY {
        return x;
    }
    let value = f64::from(x);
    let tail = activation_exp_negative(-value.abs());
    (if value >= 0.0 {
        value / (1.0 + tail)
    } else {
        value * tail / (1.0 + tail)
    }) as f32
}

fn activation_tanh(x: f32) -> f32 {
    if x.is_nan() {
        return f32::from_bits(0x7fc0_0000);
    }
    let a = f64::from(x).abs();
    // At this threshold |tanh(x)-x| is below half a binary32 ulp.
    // Preserve signed zeros and subnormals without cancellation in 1-exp(-2a).
    if a <= 0.0001220703125 {
        return x;
    }
    if a >= 16.0 {
        return 1.0_f32.copysign(x);
    }
    let tail = activation_exp_negative(-2.0 * a);
    (((1.0 - tail) / (1.0 + tail)) as f32).copysign(x)
}

fn activation_gelu(x: f32, approximate_tanh: bool) -> f32 {
    if x.is_nan() || x == f32::NEG_INFINITY {
        return f32::from_bits(0x7fc0_0000);
    }
    if x == f32::INFINITY {
        return x;
    }
    let value = f64::from(x);
    let a = value.abs();
    // Beyond this bound either mode rounds to x or signed zero in binary32.
    // Branch before forming powers, avoiding overflow on arbitrary finite inputs.
    if a >= 16.0 {
        return if x > 0.0 { x } else { -0.0 };
    }
    let tail = if approximate_tanh {
        let argument = 0.7978845608028654 * (a + 0.044715 * a * a * a);
        let exponential = activation_exp_negative(-2.0 * argument);
        exponential / (1.0 + exponential)
    } else {
        activation_normal_tail(a)
    };
    (if x < 0.0 {
        value * tail
    } else {
        value * (1.0 - tail)
    }) as f32
}

fn activation_tanh_mode(node: &fss_model_ir::GraphNode) -> Result<bool, ExecError> {
    match node.attributes().get("approximate") {
        None => Ok(false),
        Some(value) => match value.as_str(node.id(), "approximate")? {
            "none" => Ok(false),
            "tanh" => Ok(true),
            _ => Err(ExecError::Ir(ModelIrError::InvalidAttribute {
                node_id: node.id().to_owned(),
                attr_name: "approximate".to_owned(),
                reason: "GELU mode must be none or tanh".to_owned(),
            })),
        },
    }
}

fn activation_work(node: &fss_model_ir::GraphNode, output: &TensorPort) -> Result<u64, ExecError> {
    // Conservatively bound the fixed scalar arithmetic, not hardware MACs or time.
    let per_element = if node.op() == OpCode::Gelu {
        if activation_tanh_mode(node)? { 96 } else { 896 }
    } else {
        80
    };
    (output.shape().num_elements()? as u64)
        .checked_mul(per_element)
        .ok_or(ExecError::ArithmeticOverflow {
            operation: "activation work bound",
        })
}

impl ScalarExecutor {
    fn execute_activation(
        node: &fss_model_ir::GraphNode,
        input: &Tensor,
        output: &TensorPort,
        generation: Generation,
        cx: &ScalarExecCx,
    ) -> Result<Tensor, ExecError> {
        cx.checkpoint("activation:begin")?;
        let source = input.to_vec::<f32>()?;
        let approximate_tanh = node.op() == OpCode::Gelu && activation_tanh_mode(node)?;
        let mut values = Vec::with_capacity(source.len());
        for (index, value) in source.into_iter().enumerate() {
            // GELU has a bounded inner continued fraction; poll between every 64
            // elements to keep its worst-case cancellation work bounded as well.
            if index % 64 == 0 {
                cx.checkpoint("activation:elements")?;
            }
            values.push(match node.op() {
                OpCode::Silu => activation_silu(value),
                OpCode::Tanh => activation_tanh(value),
                OpCode::Gelu => activation_gelu(value, approximate_tanh),
                OpCode::Add
                | OpCode::Sub
                | OpCode::Mul
                | OpCode::Div
                | OpCode::Relu
                | OpCode::Sigmoid
                | OpCode::MatMul
                | OpCode::Reshape
                | OpCode::Transpose
                | OpCode::Squeeze
                | OpCode::Unsqueeze
                | OpCode::Concat
                | OpCode::Slice
                | OpCode::LayerNorm
                | OpCode::RMSNorm
                | OpCode::Softmax
                | OpCode::Conv2d
                | OpCode::MaxPool2d
                | OpCode::Embedding => {
                    return Err(ExecError::UnsupportedOperator {
                        node_id: node.id().to_owned(),
                        op: node.op(),
                    });
                }
            });
        }
        cx.checkpoint("activation:publish")?;
        Tensor::from_values(output.shape().clone(), &values, generation).map_err(ExecError::Tensor)
    }
}

// Frozen embedding inference is an exact table lookup, not a vector approximation,
// identity assertion or training operation. padding_idx never overwrites an imported row.
// Read through tensor views so offsets/strides remain authoritative; do not clone an
// entire vocabulary table or coerce integer IDs through a floating-point representation.
impl ScalarExecutor {
    fn execute_embedding(
        node: &fss_model_ir::GraphNode,
        indices: &Tensor,
        weights: &Tensor,
        output: &TensorPort,
        generation: Generation,
        cx: &ScalarExecCx,
    ) -> Result<Tensor, ExecError> {
        match indices.dtype() {
            DType::I8 => Self::execute_embedding_indices::<i8>(
                node, indices, weights, output, generation, cx,
            ),
            DType::I16 => Self::execute_embedding_indices::<i16>(
                node, indices, weights, output, generation, cx,
            ),
            DType::I32 => Self::execute_embedding_indices::<i32>(
                node, indices, weights, output, generation, cx,
            ),
            DType::I64 => Self::execute_embedding_indices::<i64>(
                node, indices, weights, output, generation, cx,
            ),
            DType::U8 => Self::execute_embedding_indices::<u8>(
                node, indices, weights, output, generation, cx,
            ),
            DType::U16 => Self::execute_embedding_indices::<u16>(
                node, indices, weights, output, generation, cx,
            ),
            DType::U32 => Self::execute_embedding_indices::<u32>(
                node, indices, weights, output, generation, cx,
            ),
            DType::U64 => Self::execute_embedding_indices::<u64>(
                node, indices, weights, output, generation, cx,
            ),
            DType::F32 | DType::F64 | DType::F16 | DType::BF16 | DType::Bool => {
                Err(ExecError::UnsupportedDType {
                    expected: DType::I64,
                    actual: indices.dtype(),
                    tensor_name: node.inputs()[0].clone(),
                })
            }
        }
    }

    fn execute_embedding_indices<I: fss_tensor::TensorScalar + TryInto<usize>>(
        node: &fss_model_ir::GraphNode,
        indices: &Tensor,
        weights: &Tensor,
        output: &TensorPort,
        generation: Generation,
        cx: &ScalarExecCx,
    ) -> Result<Tensor, ExecError> {
        cx.checkpoint("embedding:begin")?;
        let rows = weights.shape().dims()[0];
        let width = weights.shape().dims()[1];
        let count = indices.num_elements()?;
        let output_bytes = output.shape().size_bytes(DType::F32)?;
        let allocation_error = || {
            ExecError::Tensor(TensorError::AllocationLimitExceeded {
                requested_bytes: output_bytes,
                max_bytes: fss_tensor::MAX_STORAGE_BYTES,
            })
        };
        if output_bytes > fss_tensor::MAX_STORAGE_BYTES {
            return Err(allocation_error());
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(output_bytes)
            .map_err(|_| allocation_error())?;
        let dims = indices.shape().dims();
        let mut coordinates = vec![0_usize; dims.len()];
        for position in 0..count {
            if position % 1024 == 0 {
                cx.checkpoint("embedding:indices")?;
            }
            let row: usize = indices
                .read_element::<I>(&coordinates)?
                .try_into()
                .map_err(|_| {
                    layout_mismatch(
                        node,
                        "embedding index is negative or exceeds addressable range",
                    )
                })?;
            if row >= rows {
                return Err(layout_mismatch(
                    node,
                    "embedding index outside weight table",
                ));
            }
            // Validate the row even when width is zero. Empty output is not permission
            // to accept an invalid ID; no clamping, wrapping or zero-filled fallback.
            for column in 0..width {
                if column % 1024 == 0 {
                    cx.checkpoint("embedding:row")?;
                }
                let value = weights.read_element::<f32>(&[row, column])?;
                bytes.extend_from_slice(&value.to_ne_bytes());
            }
            for axis in (0..dims.len()).rev() {
                coordinates[axis] += 1;
                if coordinates[axis] < dims[axis] {
                    break;
                }
                coordinates[axis] = 0;
            }
        }
        if bytes.len() != output_bytes {
            return Err(layout_mismatch(
                node,
                "embedding output byte count mismatch",
            ));
        }
        cx.checkpoint("embedding:publish")?;
        // Transfer the one bounded output buffer into immutable tensor storage. This
        // avoids a second full output copy and retains F32 payload bits exactly.
        let storage = std::sync::Arc::new(fss_tensor::TensorStorage::from_vec(bytes, generation)?);
        let strides = fss_tensor::Strides::from_shape_row_major(output.shape())?;
        let view = fss_tensor::TensorView::new(
            storage,
            0,
            DType::F32,
            output.shape().clone(),
            strides,
            generation,
        )?;
        Ok(Tensor::from_view(view))
    }
}

#[cfg(test)]
mod embedding_smoke_tests {
    use super::*;
    use fss_model_ir::{AttributeMap, GraphNode};

    fn graph(dtype: DType, width: usize) -> Result<ModelIrGraph, Box<dyn std::error::Error>> {
        let generation = Generation::from_u64(1);
        Ok(ModelIrGraph::builder("embedding-smoke", generation)
            .add_input(TensorPort::new(
                "ids",
                dtype,
                Shape::new(vec![3])?,
                generation,
            )?)
            .add_input(TensorPort::new(
                "table",
                DType::F32,
                Shape::new(vec![3, width])?,
                generation,
            )?)
            .add_output(TensorPort::new(
                "out",
                DType::F32,
                Shape::new(vec![3, width])?,
                generation,
            )?)
            .add_node(GraphNode::new(
                "lookup",
                OpCode::Embedding,
                "lookup",
                vec!["ids".to_owned(), "table".to_owned()],
                vec!["out".to_owned()],
                AttributeMap::new(),
            )?)
            .build_and_validate()?)
    }

    #[test]
    fn embedding_executes_in_the_existing_scalar_entrypoint()
    -> Result<(), Box<dyn std::error::Error>> {
        let graph = graph(DType::I64, 2)?;
        let generation = graph.generation();
        let ids = Tensor::from_values(Shape::new(vec![3])?, &[2_i64, 0, 2], generation)?;
        let table = Tensor::from_values(
            Shape::new(vec![3, 2])?,
            &[1_f32, 2., 3., 4., 5., 6.],
            generation,
        )?;
        let result = ScalarExecutor::run(
            &graph,
            &[("ids", ids), ("table", table)],
            ExecBudget::new(36, 72),
            &ScalarExecCx::new(),
        )?;
        assert_eq!(
            result
                .get_output("out")
                .ok_or("missing output")?
                .to_vec::<f32>()?,
            vec![5., 6., 1., 2., 5., 6.]
        );
        assert_eq!(result.executed_macs(), 36);
        assert_eq!(result.allocated_bytes(), 72);
        assert_eq!(result.nodes_executed(), 1);
        Ok(())
    }

    #[test]
    fn zero_width_embedding_still_refuses_invalid_indices() -> Result<(), Box<dyn std::error::Error>>
    {
        let graph = graph(DType::I64, 0)?;
        let generation = graph.generation();
        let table = Tensor::from_values(Shape::new(vec![3, 0])?, &[] as &[f32], generation)?;
        for ids in [[0_i64, 1, -1], [0, 1, 3]] {
            let ids = Tensor::from_values(Shape::new(vec![3])?, &ids, generation)?;
            assert!(matches!(
                ScalarExecutor::run(
                    &graph,
                    &[("ids", ids), ("table", table.clone())],
                    ExecBudget::unlimited(),
                    &ScalarExecCx::new()
                ),
                Err(ExecError::ShapeMismatch { .. })
            ));
        }
        Ok(())
    }
}

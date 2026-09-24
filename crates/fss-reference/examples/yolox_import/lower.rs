//! Exact lowering of the admitted YOLOX-Nano ONNX operator subset onto frozen FSS Model IR v1.
//!
//! Every ONNX operator either maps to one IR operator with identical semantics or is lowered to
//! an exact composition of IR operators; anything else is refused by name. No operator is
//! approximated and no numeric value is changed, except that `x * Sigmoid(x)` is recognized as
//! IR SiLU (the same function, evaluated by the reference kernel in binary64 and rounded once).
//!
//! * `Resize` (nearest, asymmetric, floor, integer scale s) is `out[i] = in[floor(i/s)]`, which is
//!   exactly Reshape `[N,C,H,1,W,1]` -> Concat (s copies) on both unit axes -> Reshape.
//! * The upstream graph expects BGR; FSS preprocessing yields RGB, so the graph begins with
//!   three channel Slices and a Concat (pure data movement).
//! * The upstream graph ends before the YOLOX grid decode. The lowering appends it:
//!   `xy = (raw_xy + grid) * stride`, `wh = exp(raw_wh) * stride`, where exp is the exact identity
//!   `exp(t) = sigmoid(t) / sigmoid(-t)` over admitted IR operators (IR v1 has no Exp operator).
//!   The raw upstream output remains a separate graph output for conformance.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::Generation;
use fss_model_ir::{
    AttrValue, AttributeMap, GraphNode, ModelIrError, ModelIrGraph, ModelIrVersion, OpCode,
    TensorPort, infer_operator_outputs,
};
use fss_tensor::{DType, Shape};

use super::onnx::{AttrValue as OnnxAttr, DT_FLOAT, DT_INT64, Model, Node, Tensor};

/// Graph input receiving FSS-preprocessed NCHW RGB.
pub const IMAGE_INPUT: &str = "image_rgb";
/// Raw upstream head output, identical in meaning to the ONNX `output`.
pub const RAW_OUTPUT: &str = "raw_head";
/// Decoded head: cx, cy, w, h (model-input pixels), objectness, 80 class probabilities.
pub const DECODED_OUTPUT: &str = "decoded_head";
/// Model tensor generation.
pub const GENERATION: Generation = Generation(1);
const STRIDES: [usize; 3] = [8, 16, 32];

/// Lowering refusal.
#[derive(Debug)]
pub enum LowerError {
    /// Operator or attribute outside the admitted exact subset.
    Unsupported(String),
    /// Graph structure contradicts itself or the declared shapes.
    Invalid(String),
    /// IR validation refused a node.
    Ir(ModelIrError),
}
impl std::fmt::Display for LowerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(s) => write!(f, "unsupported: {s}"),
            Self::Invalid(s) => write!(f, "invalid: {s}"),
            Self::Ir(e) => write!(f, "IR refused: {e}"),
        }
    }
}
impl std::error::Error for LowerError {}
impl From<ModelIrError> for LowerError {
    fn from(e: ModelIrError) -> Self {
        Self::Ir(e)
    }
}
type Result<T> = std::result::Result<T, LowerError>;

fn unsupported<T>(s: impl Into<String>) -> Result<T> {
    Err(LowerError::Unsupported(s.into()))
}
fn invalid<T>(s: impl Into<String>) -> Result<T> {
    Err(LowerError::Invalid(s.into()))
}

/// Complete lowering result.
pub struct Lowered {
    /// Validated IR graph.
    pub graph: ModelIrGraph,
    /// Parameter name -> (shape, F32 values), exactly the non-image graph inputs.
    pub parameters: BTreeMap<String, (Vec<usize>, Vec<f32>)>,
    /// ONNX operator histogram.
    pub onnx_ops: BTreeMap<String, usize>,
    /// Emitted IR operator histogram.
    pub ir_ops: BTreeMap<String, usize>,
    /// Number of Sigmoid+Mul pairs recognized as SiLU.
    pub silu_fused: usize,
    /// Number of Resize nodes lowered to Reshape/Concat.
    pub resize_lowered: usize,
}

struct Builder {
    ports: BTreeMap<String, TensorPort>,
    params: BTreeMap<String, (Vec<usize>, Vec<f32>)>,
    nodes: Vec<GraphNode>,
    ir_ops: BTreeMap<String, usize>,
}

fn ints(v: &[usize]) -> AttrValue {
    AttrValue::IntList(v.iter().map(|&n| n as i64).collect())
}

impl Builder {
    fn dims(&self, name: &str) -> Result<Vec<usize>> {
        self.ports
            .get(name)
            .map(|p| p.shape().dims().to_vec())
            .ok_or_else(|| LowerError::Invalid(format!("unknown tensor {name}")))
    }
    fn param(&mut self, name: String, dims: Vec<usize>, values: Vec<f32>) -> Result<String> {
        if let Some((d, v)) = self.params.get(&name) {
            if *d != dims
                || v.iter()
                    .map(|x| x.to_bits())
                    .ne(values.iter().map(|x| x.to_bits()))
            {
                return invalid(format!(
                    "parameter {name} bound twice with different values"
                ));
            }
            return Ok(name);
        }
        if values.iter().any(|v| !v.is_finite()) {
            return invalid(format!("nonfinite parameter {name}"));
        }
        let port = TensorPort::new(
            name.clone(),
            DType::F32,
            Shape::new(dims.clone()).map_err(ModelIrError::from)?,
            GENERATION,
        )?;
        self.ports.insert(name.clone(), port);
        self.params.insert(name.clone(), (dims, values));
        Ok(name)
    }
    fn node(
        &mut self,
        op: OpCode,
        label: &str,
        inputs: Vec<String>,
        output: String,
        attrs: AttributeMap,
    ) -> Result<()> {
        let id = format!("n{:04}", self.nodes.len());
        let ports = inputs
            .iter()
            .map(|n| {
                self.ports
                    .get(n)
                    .ok_or_else(|| LowerError::Invalid(format!("unknown input {n}")))
            })
            .collect::<Result<Vec<_>>>()?;
        let out = infer_operator_outputs(
            &id,
            op,
            &ports,
            std::slice::from_ref(&output),
            &attrs,
            GENERATION,
        )?;
        let port = out
            .into_iter()
            .next()
            .ok_or_else(|| LowerError::Invalid("no output".into()))?;
        if self.ports.insert(output.clone(), port).is_some() {
            return invalid(format!("tensor {output} produced twice"));
        }
        *self.ir_ops.entry(op.stable_id().to_owned()).or_default() += 1;
        self.nodes
            .push(GraphNode::new(id, op, label, inputs, vec![output], attrs)?);
        Ok(())
    }
    fn slice(
        &mut self,
        label: &str,
        input: String,
        output: String,
        axis: usize,
        range: std::ops::Range<usize>,
    ) -> Result<()> {
        let mut a = AttributeMap::new();
        a.insert("axes".into(), ints(&[axis]));
        a.insert("starts".into(), ints(&[range.start]));
        a.insert("ends".into(), ints(&[range.end]));
        a.insert("steps".into(), ints(&[1]));
        self.node(OpCode::Slice, label, vec![input], output, a)
    }
    fn concat(
        &mut self,
        label: &str,
        inputs: Vec<String>,
        output: String,
        axis: usize,
    ) -> Result<()> {
        let mut a = AttributeMap::new();
        a.insert("axis".into(), AttrValue::Int(axis as i64));
        self.node(OpCode::Concat, label, inputs, output, a)
    }
    fn reshape(
        &mut self,
        label: &str,
        input: String,
        output: String,
        shape: &[usize],
    ) -> Result<()> {
        let mut a = AttributeMap::new();
        a.insert("shape".into(), ints(shape));
        self.node(OpCode::Reshape, label, vec![input], output, a)
    }
    fn binary(
        &mut self,
        op: OpCode,
        label: &str,
        a: String,
        b: String,
        output: String,
    ) -> Result<()> {
        self.node(op, label, vec![a, b], output, AttributeMap::new())
    }
}

fn attr_int(node: &Node, name: &str, default: Option<i64>) -> Result<i64> {
    match node.attr(name) {
        Some(OnnxAttr::Int(v)) => Ok(*v),
        Some(_) => invalid(format!(
            "{} attribute {name} is not an integer",
            node.op_type
        )),
        None => {
            default.ok_or_else(|| LowerError::Invalid(format!("{} requires {name}", node.op_type)))
        }
    }
}
fn attr_ints(node: &Node, name: &str, default: Option<Vec<i64>>) -> Result<Vec<i64>> {
    match node.attr(name) {
        Some(OnnxAttr::Ints(v)) => Ok(v.clone()),
        Some(_) => invalid(format!(
            "{} attribute {name} is not an integer list",
            node.op_type
        )),
        None => {
            default.ok_or_else(|| LowerError::Invalid(format!("{} requires {name}", node.op_type)))
        }
    }
}
fn attr_text(node: &Node, name: &str) -> Result<Option<String>> {
    match node.attr(name) {
        Some(OnnxAttr::Text(v)) => {
            Ok(Some(String::from_utf8(v.clone()).map_err(|_| {
                LowerError::Invalid("non-UTF-8 attribute".into())
            })?))
        }
        Some(_) => invalid(format!("{} attribute {name} is not a string", node.op_type)),
        None => Ok(None),
    }
}
fn only_attrs(node: &Node, allowed: &[&str]) -> Result<()> {
    for a in &node.attributes {
        if !allowed.contains(&a.name.as_str()) {
            return unsupported(format!(
                "{} attribute {} = {}",
                node.op_type,
                a.name,
                a.value.describe()
            ));
        }
    }
    Ok(())
}
fn usizes(v: &[i64], what: &str) -> Result<Vec<usize>> {
    v.iter()
        .map(|&n| usize::try_from(n).map_err(|_| LowerError::Invalid(format!("negative {what}"))))
        .collect()
}
fn axis(raw: i64, rank: usize) -> Result<usize> {
    let a = if raw < 0 { raw + rank as i64 } else { raw };
    usize::try_from(a)
        .ok()
        .filter(|a| *a < rank)
        .ok_or_else(|| LowerError::Invalid(format!("axis {raw} for rank {rank}")))
}

/// Lower a parsed model. `input_hw` is the expected static image size.
pub fn lower(model: &Model, input_hw: [usize; 2]) -> Result<Lowered> {
    if model
        .opsets
        .iter()
        .any(|(d, v)| !d.is_empty() || !(11..=13).contains(v))
    {
        return unsupported(format!("opsets {:?}", model.opsets));
    }
    let g = &model.graph;
    let inits: BTreeMap<&str, &Tensor> = g
        .initializers
        .iter()
        .map(|t| (t.name.as_str(), t))
        .collect();
    let data_inputs: Vec<_> = g
        .inputs
        .iter()
        .filter(|v| !inits.contains_key(v.name.as_str()))
        .collect();
    let [h, w] = input_hw;
    if data_inputs.len() != 1
        || data_inputs[0].elem_type != DT_FLOAT
        || data_inputs[0].dims != [1, 3, h as i64, w as i64]
    {
        return invalid("expected one F32 [1,3,H,W] data input");
    }
    if g.outputs.len() != 1 {
        return invalid("expected one graph output");
    }
    let onnx_input = data_inputs[0].name.clone();
    let onnx_output = g.outputs[0].name.clone();
    let name = |t: &str| {
        if t == onnx_output {
            RAW_OUTPUT.to_owned()
        } else {
            format!("onnx:{t}")
        }
    };

    let mut onnx_ops = BTreeMap::new();
    for n in &g.nodes {
        *onnx_ops.entry(n.op_type.clone()).or_insert(0_usize) += 1;
    }
    // Consumer counts decide which Sigmoid outputs exist only to form x * sigmoid(x).
    let mut consumers: BTreeMap<&str, usize> = BTreeMap::new();
    for n in &g.nodes {
        for i in &n.inputs {
            *consumers.entry(i.as_str()).or_default() += 1;
        }
    }
    *consumers.entry(onnx_output.as_str()).or_default() += 1;
    let producer: BTreeMap<&str, usize> = g
        .nodes
        .iter()
        .enumerate()
        .flat_map(|(i, n)| n.outputs.iter().map(move |o| (o.as_str(), i)))
        .collect();
    let mut fused_sigmoids = BTreeSet::new();
    let mut silu_of: BTreeMap<usize, String> = BTreeMap::new();
    for (i, n) in g.nodes.iter().enumerate() {
        if n.op_type != "Mul" || n.inputs.len() != 2 {
            continue;
        }
        for (x, s) in [(0, 1), (1, 0)] {
            let Some(&p) = producer.get(n.inputs[s].as_str()) else {
                continue;
            };
            let sig = &g.nodes[p];
            if sig.op_type == "Sigmoid"
                && sig.inputs.len() == 1
                && sig.inputs[0] == n.inputs[x]
                && sig.attributes.is_empty()
                && consumers.get(n.inputs[s].as_str()) == Some(&1)
            {
                fused_sigmoids.insert(p);
                silu_of.insert(i, n.inputs[x].clone());
                break;
            }
        }
    }

    let mut b = Builder {
        ports: BTreeMap::new(),
        params: BTreeMap::new(),
        nodes: Vec::new(),
        ir_ops: BTreeMap::new(),
    };
    b.ports.insert(
        IMAGE_INPUT.to_owned(),
        TensorPort::new(
            IMAGE_INPUT,
            DType::F32,
            Shape::new(vec![1, 3, h, w]).map_err(ModelIrError::from)?,
            GENERATION,
        )?,
    );
    // FSS preprocessing is RGB; the upstream weights were trained on BGR (OpenCV) order.
    for (c, t) in [(2, "fss:b"), (1, "fss:g"), (0, "fss:r")] {
        b.slice(
            "rgb_to_bgr",
            IMAGE_INPUT.to_owned(),
            t.to_owned(),
            1,
            c..c + 1,
        )?;
    }
    b.concat(
        "rgb_to_bgr",
        vec!["fss:b".into(), "fss:g".into(), "fss:r".into()],
        name(&onnx_input),
        1,
    )?;

    let constant = |t: &str| inits.get(t).copied();
    let mut resize_lowered = 0;
    for (i, n) in g.nodes.iter().enumerate() {
        let label = if n.name.is_empty() {
            n.op_type.clone()
        } else {
            n.name.clone()
        };
        if n.outputs.len() != 1 {
            return unsupported(format!("{} with {} outputs", n.op_type, n.outputs.len()));
        }
        let out = name(&n.outputs[0]);
        match n.op_type.as_str() {
            "Sigmoid" if fused_sigmoids.contains(&i) => {}
            "Mul" if silu_of.contains_key(&i) => {
                let x = silu_of
                    .get(&i)
                    .map(|x| name(x))
                    .ok_or_else(|| LowerError::Invalid("silu".into()))?;
                b.node(OpCode::Silu, &label, vec![x], out, AttributeMap::new())?;
            }
            "Sigmoid" => {
                only_attrs(n, &[])?;
                b.node(
                    OpCode::Sigmoid,
                    &label,
                    vec![name(&n.inputs[0])],
                    out,
                    AttributeMap::new(),
                )?;
            }
            "Add" | "Mul" | "Sub" | "Div" => {
                only_attrs(n, &[])?;
                let op = match n.op_type.as_str() {
                    "Add" => OpCode::Add,
                    "Mul" => OpCode::Mul,
                    "Sub" => OpCode::Sub,
                    _ => OpCode::Div,
                };
                let mut args = Vec::new();
                for input in &n.inputs {
                    args.push(match constant(input) {
                        Some(t) if t.data_type == DT_FLOAT => {
                            b.param(name(input), usizes(&t.dims, "dim")?, t.floats.clone())?
                        }
                        Some(_) => return unsupported("non-F32 arithmetic constant"),
                        None => name(input),
                    });
                }
                if args.len() != 2 {
                    return invalid("binary arity");
                }
                let second = args
                    .pop()
                    .ok_or_else(|| LowerError::Invalid("arity".into()))?;
                let first = args
                    .pop()
                    .ok_or_else(|| LowerError::Invalid("arity".into()))?;
                b.binary(op, &label, first, second, out)?;
            }
            "Conv" => {
                only_attrs(
                    n,
                    &[
                        "dilations",
                        "group",
                        "kernel_shape",
                        "pads",
                        "strides",
                        "auto_pad",
                    ],
                )?;
                if attr_text(n, "auto_pad")?.is_some_and(|p| p != "NOTSET") {
                    return unsupported("Conv auto_pad");
                }
                let weight = n.inputs.get(1).and_then(|t| constant(t)).ok_or_else(|| {
                    LowerError::Unsupported("Conv weight must be constant".into())
                })?;
                let wd = usizes(&weight.dims, "weight dim")?;
                if wd.len() != 4 || weight.data_type != DT_FLOAT {
                    return unsupported("Conv weight rank/type");
                }
                if usizes(
                    &attr_ints(n, "kernel_shape", Some(vec![wd[2] as i64, wd[3] as i64]))?,
                    "kernel",
                )? != wd[2..]
                {
                    return invalid("Conv kernel_shape disagrees with weight");
                }
                let mut inputs = vec![
                    name(&n.inputs[0]),
                    b.param(name(&n.inputs[1]), wd, weight.floats.clone())?,
                ];
                if let Some(bias_name) = n.inputs.get(2).filter(|s| !s.is_empty()) {
                    let bias = constant(bias_name)
                        .filter(|t| t.data_type == DT_FLOAT)
                        .ok_or_else(|| {
                            LowerError::Unsupported("Conv bias must be a constant F32".into())
                        })?;
                    inputs.push(b.param(
                        name(bias_name),
                        usizes(&bias.dims, "bias dim")?,
                        bias.floats.clone(),
                    )?);
                }
                let mut a = AttributeMap::new();
                a.insert(
                    "dilations".into(),
                    ints(&usizes(
                        &attr_ints(n, "dilations", Some(vec![1, 1]))?,
                        "dilation",
                    )?),
                );
                a.insert(
                    "groups".into(),
                    AttrValue::Int(attr_int(n, "group", Some(1))?),
                );
                a.insert(
                    "padding".into(),
                    ints(&usizes(&attr_ints(n, "pads", Some(vec![0; 4]))?, "pad")?),
                );
                a.insert(
                    "strides".into(),
                    ints(&usizes(
                        &attr_ints(n, "strides", Some(vec![1, 1]))?,
                        "stride",
                    )?),
                );
                b.node(OpCode::Conv2d, &label, inputs, out, a)?;
            }
            "MaxPool" => {
                only_attrs(
                    n,
                    &[
                        "ceil_mode",
                        "kernel_shape",
                        "pads",
                        "strides",
                        "auto_pad",
                        "dilations",
                        "storage_order",
                    ],
                )?;
                if attr_int(n, "ceil_mode", Some(0))? != 0
                    || attr_int(n, "storage_order", Some(0))? != 0
                    || attr_ints(n, "dilations", Some(vec![1, 1]))? != [1, 1]
                    || attr_text(n, "auto_pad")?.is_some_and(|p| p != "NOTSET")
                {
                    return unsupported("MaxPool ceil_mode/dilations/storage_order/auto_pad");
                }
                let mut a = AttributeMap::new();
                a.insert(
                    "kernel_size".into(),
                    ints(&usizes(&attr_ints(n, "kernel_shape", None)?, "kernel")?),
                );
                a.insert(
                    "padding".into(),
                    ints(&usizes(&attr_ints(n, "pads", Some(vec![0; 4]))?, "pad")?),
                );
                a.insert(
                    "strides".into(),
                    ints(&usizes(
                        &attr_ints(n, "strides", Some(vec![1, 1]))?,
                        "stride",
                    )?),
                );
                b.node(OpCode::MaxPool2d, &label, vec![name(&n.inputs[0])], out, a)?;
            }
            "Concat" => {
                only_attrs(n, &["axis"])?;
                let x = name(&n.inputs[0]);
                let rank = b.dims(&x)?.len();
                let ax = axis(attr_int(n, "axis", None)?, rank)?;
                b.concat(&label, n.inputs.iter().map(|t| name(t)).collect(), out, ax)?;
            }
            "Transpose" => {
                only_attrs(n, &["perm"])?;
                let mut a = AttributeMap::new();
                a.insert(
                    "permutation".into(),
                    ints(&usizes(&attr_ints(n, "perm", None)?, "perm")?),
                );
                b.node(OpCode::Transpose, &label, vec![name(&n.inputs[0])], out, a)?;
            }
            "Reshape" => {
                only_attrs(n, &["allowzero"])?;
                if attr_int(n, "allowzero", Some(0))? != 0 {
                    return unsupported("Reshape allowzero");
                }
                let x = name(&n.inputs[0]);
                let in_dims = b.dims(&x)?;
                let shape = n
                    .inputs
                    .get(1)
                    .and_then(|t| constant(t))
                    .filter(|t| t.data_type == DT_INT64)
                    .ok_or_else(|| {
                        LowerError::Unsupported("Reshape shape must be a constant INT64".into())
                    })?;
                let total: usize = in_dims.iter().product();
                let mut dims = Vec::with_capacity(shape.ints.len());
                let mut infer = None;
                for (k, &d) in shape.ints.iter().enumerate() {
                    dims.push(match d {
                        0 => *in_dims
                            .get(k)
                            .ok_or_else(|| LowerError::Invalid("Reshape 0 beyond rank".into()))?,
                        -1 if infer.is_none() => {
                            infer = Some(k);
                            1
                        }
                        d if d > 0 => d as usize,
                        _ => return invalid("Reshape dimension"),
                    });
                }
                if let Some(k) = infer {
                    let known: usize = dims.iter().product();
                    if known == 0 || !total.is_multiple_of(known) {
                        return invalid("Reshape -1 not divisible");
                    }
                    dims[k] = total / known;
                }
                b.reshape(&label, x, out, &dims)?;
            }
            "Slice" => {
                only_attrs(n, &[])?;
                let x = name(&n.inputs[0]);
                let in_dims = b.dims(&x)?;
                let get = |k: usize| -> Result<Option<&Tensor>> {
                    match n.inputs.get(k).filter(|s| !s.is_empty()) {
                        None => Ok(None),
                        Some(t) => constant(t)
                            .filter(|t| t.data_type == DT_INT64)
                            .map(Some)
                            .ok_or_else(|| {
                                LowerError::Unsupported(
                                    "Slice parameters must be constant INT64".into(),
                                )
                            }),
                    }
                };
                let starts = get(1)?
                    .ok_or_else(|| LowerError::Invalid("Slice starts".into()))?
                    .ints
                    .clone();
                let ends = get(2)?
                    .ok_or_else(|| LowerError::Invalid("Slice ends".into()))?
                    .ints
                    .clone();
                let axes = match get(3)? {
                    Some(t) => t.ints.clone(),
                    None => (0..starts.len() as i64).collect(),
                };
                let steps = match get(4)? {
                    Some(t) => t.ints.clone(),
                    None => vec![1; starts.len()],
                };
                if [ends.len(), axes.len(), steps.len()]
                    .iter()
                    .any(|l| *l != starts.len())
                {
                    return invalid("Slice lengths");
                }
                let (mut ax, mut st, mut en, mut sp) =
                    (Vec::new(), Vec::new(), Vec::new(), Vec::new());
                for k in 0..starts.len() {
                    let a = axis(axes[k], in_dims.len())?;
                    let dim = in_dims[a] as i64;
                    if steps[k] <= 0 {
                        return unsupported("Slice with non-positive step");
                    }
                    let clamp = |v: i64| (if v < 0 { v + dim } else { v }).clamp(0, dim) as usize;
                    let s = clamp(starts[k]);
                    let e = clamp(ends[k]).max(s);
                    ax.push(a);
                    st.push(s);
                    en.push(e);
                    sp.push(steps[k] as usize);
                }
                let mut a = AttributeMap::new();
                a.insert("axes".into(), ints(&ax));
                a.insert("starts".into(), ints(&st));
                a.insert("ends".into(), ints(&en));
                a.insert("steps".into(), ints(&sp));
                b.node(OpCode::Slice, &label, vec![x], out, a)?;
            }
            "Resize" => {
                only_attrs(
                    n,
                    &[
                        "coordinate_transformation_mode",
                        "cubic_coeff_a",
                        "mode",
                        "nearest_mode",
                        "exclude_outside",
                        "extrapolation_value",
                    ],
                )?;
                if attr_text(n, "mode")?.as_deref() != Some("nearest")
                    || attr_text(n, "coordinate_transformation_mode")?.as_deref()
                        != Some("asymmetric")
                    || attr_text(n, "nearest_mode")?.as_deref() != Some("floor")
                    || attr_int(n, "exclude_outside", Some(0))? != 0
                {
                    return unsupported("Resize other than nearest/asymmetric/floor");
                }
                if n.inputs.len() > 3 && !n.inputs[3].is_empty() {
                    return unsupported("Resize by sizes");
                }
                if let Some(roi) = n.inputs.get(1).filter(|s| !s.is_empty())
                    && constant(roi).is_none()
                {
                    return unsupported("Resize roi must be constant (ignored for asymmetric)");
                }
                let scales = n
                    .inputs
                    .get(2)
                    .and_then(|t| constant(t))
                    .filter(|t| t.data_type == DT_FLOAT)
                    .ok_or_else(|| {
                        LowerError::Unsupported("Resize scales must be constant F32".into())
                    })?;
                let x = name(&n.inputs[0]);
                let d = b.dims(&x)?;
                if d.len() != 4
                    || scales.floats.len() != 4
                    || scales.floats[0] != 1.0
                    || scales.floats[1] != 1.0
                {
                    return unsupported("Resize must scale only the two spatial axes of NCHW");
                }
                let factor = |s: f32| -> Result<usize> {
                    if (1.0..=64.0).contains(&s) && s.fract() == 0.0 {
                        Ok(s as usize)
                    } else {
                        unsupported(format!("Resize scale {s}"))
                    }
                };
                let (sh, sw) = (factor(scales.floats[2])?, factor(scales.floats[3])?);
                let base = format!("{out}:resize");
                b.reshape(
                    &label,
                    x,
                    format!("{base}:unit"),
                    &[d[0], d[1], d[2], 1, d[3], 1],
                )?;
                b.concat(
                    &label,
                    vec![format!("{base}:unit"); sw],
                    format!("{base}:w"),
                    5,
                )?;
                b.concat(
                    &label,
                    vec![format!("{base}:w"); sh],
                    format!("{base}:hw"),
                    3,
                )?;
                b.reshape(
                    &label,
                    format!("{base}:hw"),
                    out,
                    &[d[0], d[1], d[2] * sh, d[3] * sw],
                )?;
                resize_lowered += 1;
            }
            other => {
                return unsupported(format!(
                    "ONNX operator {other} (BatchNormalization is not folded here: this source has none)"
                ));
            }
        }
    }

    // Grid decode appended after the unchanged upstream head.
    let raw = b.dims(RAW_OUTPUT)?;
    let rows: usize = STRIDES.iter().map(|s| (h / s) * (w / s)).sum();
    if raw.len() != 3 || raw[0] != 1 || raw[1] != rows || raw[2] < 5 {
        return invalid(format!(
            "upstream head {raw:?} is not [1,{rows},4+1+classes]"
        ));
    }
    let mut grid = Vec::with_capacity(rows * 2);
    let mut stride = Vec::with_capacity(rows);
    for s in STRIDES {
        for gy in 0..h / s {
            for gx in 0..w / s {
                grid.push(gx as f32);
                grid.push(gy as f32);
                stride.push(s as f32);
            }
        }
    }
    let grid = b.param("fss:decode_grid".into(), vec![1, rows, 2], grid)?;
    let stride = b.param("fss:decode_stride".into(), vec![1, rows, 1], stride)?;
    let neg = b.param("fss:decode_negative_one".into(), vec![1, 1, 1], vec![-1.0])?;
    let fields = raw[2];
    b.slice("decode", RAW_OUTPUT.into(), "fss:raw_xy".into(), 2, 0..2)?;
    b.slice("decode", RAW_OUTPUT.into(), "fss:raw_wh".into(), 2, 2..4)?;
    b.slice(
        "decode",
        RAW_OUTPUT.into(),
        "fss:raw_scores".into(),
        2,
        4..fields,
    )?;
    b.binary(
        OpCode::Add,
        "decode_xy",
        "fss:raw_xy".into(),
        grid,
        "fss:grid_xy".into(),
    )?;
    b.binary(
        OpCode::Mul,
        "decode_xy",
        "fss:grid_xy".into(),
        stride.clone(),
        "fss:xy".into(),
    )?;
    b.binary(
        OpCode::Mul,
        "decode_wh_exp",
        "fss:raw_wh".into(),
        neg,
        "fss:neg_wh".into(),
    )?;
    b.node(
        OpCode::Sigmoid,
        "decode_wh_exp",
        vec!["fss:raw_wh".into()],
        "fss:sig_pos".into(),
        AttributeMap::new(),
    )?;
    b.node(
        OpCode::Sigmoid,
        "decode_wh_exp",
        vec!["fss:neg_wh".into()],
        "fss:sig_neg".into(),
        AttributeMap::new(),
    )?;
    b.binary(
        OpCode::Div,
        "decode_wh_exp",
        "fss:sig_pos".into(),
        "fss:sig_neg".into(),
        "fss:exp_wh".into(),
    )?;
    b.binary(
        OpCode::Mul,
        "decode_wh",
        "fss:exp_wh".into(),
        stride,
        "fss:wh".into(),
    )?;
    b.concat(
        "decode",
        vec!["fss:xy".into(), "fss:wh".into(), "fss:raw_scores".into()],
        DECODED_OUTPUT.into(),
        2,
    )?;

    let mut inputs = vec![
        b.ports
            .get(IMAGE_INPUT)
            .cloned()
            .ok_or_else(|| LowerError::Invalid("image".into()))?,
    ];
    for name in b.params.keys() {
        inputs.push(
            b.ports
                .get(name)
                .cloned()
                .ok_or_else(|| LowerError::Invalid("param".into()))?,
        );
    }
    let outputs = [RAW_OUTPUT, DECODED_OUTPUT]
        .iter()
        .map(|n| {
            b.ports
                .get(*n)
                .cloned()
                .ok_or_else(|| LowerError::Invalid("output".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    let graph = ModelIrGraph::new_validated(
        "model:yolox-nano:coco80:416",
        ModelIrVersion::V1,
        GENERATION,
        inputs,
        outputs,
        b.nodes,
    )?;
    Ok(Lowered {
        graph,
        parameters: b.params,
        onnx_ops,
        ir_ops: b.ir_ops,
        silu_fused: silu_of.len(),
        resize_lowered,
    })
}

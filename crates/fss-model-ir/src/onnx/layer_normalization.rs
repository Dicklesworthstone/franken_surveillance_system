#![forbid(unsafe_code)]
//! LayerNormalization-17 with F32 inputs and stash_type=1.
//!
//! https://onnx.ai/onnx/operators/onnx__LayerNormalization.html#layernormalization-17
//! Preserve the function's separately rounded F32 arithmetic, including its
//! reciprocal followed by multiplication. The frozen native LayerNorm uses
//! binary64 statistics and is deliberately not substituted. The two means use
//! the same ordered F32 MatMul/Div reduction convention as imported ReduceMean.
//! All helpers and shared reduction constants are admitted before allocation.

use fss_tensor::{DType, Tensor};

use super::{Lowering, OnnxError, Result, SourceNode, port};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

fn ints(dims: &[usize]) -> Result<AttrValue> {
    Ok(AttrValue::IntList(
        dims.iter()
            .map(|&dim| i64::try_from(dim).map_err(|_| OnnxError::Limit))
            .collect::<Result<Vec<_>>>()?,
    ))
}

fn append(
    source: &SourceNode<'_>,
    lowering: &mut Lowering<'_, '_>,
    suffix: Option<&str>,
    op: OpCode,
    inputs: Vec<String>,
    attrs: AttributeMap,
) -> Result<String> {
    let (id, output) = if let Some(suffix) = suffix {
        let id = format!("{}-layernorm-{suffix}", source.id);
        let output = lowering.fresh_name(&id)?;
        (id, output)
    } else {
        (source.id.clone(), source.outputs[0].clone())
    };
    lowering.append(
        GraphNode::new(
            id,
            op,
            source.label.clone(),
            inputs,
            vec![output.clone()],
            attrs,
        )
        .map_err(|_| OnnxError::Graph)?,
    )?;
    Ok(output)
}

fn scalar(
    source: &SourceNode<'_>,
    lowering: &mut Lowering<'_, '_>,
    suffix: &str,
    value: f32,
) -> Result<String> {
    let name = lowering.fresh_name(&format!("{}-layernorm-{suffix}", source.id))?;
    let scalar = port(
        name.clone(),
        Vec::new(),
        lowering.generation,
        lowering.admission,
    )?;
    lowering.admission.charge(4)?;
    let tensor = Tensor::from_values(scalar.shape().clone(), &[value], lowering.generation)
        .map_err(|_| OnnxError::Limit)?;
    lowering.add_constant(scalar, tensor)?;
    Ok(name)
}

struct Reduction {
    matrix: [usize; 2],
    output: Vec<usize>,
    flatten: bool,
    restore: bool,
    ones: String,
    divisor: String,
}

fn mean(
    source: &SourceNode<'_>,
    lowering: &mut Lowering<'_, '_>,
    reduction: &Reduction,
    input: String,
    prefix: &str,
) -> Result<String> {
    let mut value = input;
    if reduction.flatten {
        value = append(
            source,
            lowering,
            Some(&format!("{prefix}-flatten")),
            OpCode::Reshape,
            vec![value],
            AttributeMap::from([("shape".into(), ints(&reduction.matrix)?)]),
        )?;
    }
    value = append(
        source,
        lowering,
        Some(&format!("{prefix}-sum")),
        OpCode::MatMul,
        vec![value, reduction.ones.clone()],
        AttributeMap::new(),
    )?;
    value = append(
        source,
        lowering,
        Some(&format!("{prefix}-divide")),
        OpCode::Div,
        vec![value, reduction.divisor.clone()],
        AttributeMap::new(),
    )?;
    if reduction.restore {
        value = append(
            source,
            lowering,
            Some(&format!("{prefix}-restore")),
            OpCode::Reshape,
            vec![value],
            AttributeMap::from([("shape".into(), ints(&reduction.output)?)]),
        )?;
    }
    Ok(value)
}

pub(super) fn lower(mut source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    if !(2..=3).contains(&source.inputs.len())
        || source.outputs.len() != 1
        || source.inputs[..2].iter().any(String::is_empty)
    {
        return Err(OnnxError::Graph);
    }
    let axis = match source.attrs.remove("axis") {
        None => -1,
        Some(AttrValue::Int(axis)) => axis,
        Some(_) => return Err(OnnxError::Graph),
    };
    let epsilon = match source.attrs.remove("epsilon") {
        None => 1e-5_f32,
        Some(AttrValue::Float(value)) if value.is_finite() && value > 0.0 => value as f32,
        Some(AttrValue::Float(_)) => return Err(OnnxError::Unsupported),
        Some(_) => return Err(OnnxError::Graph),
    };
    match source.attrs.remove("stash_type") {
        None | Some(AttrValue::Int(1)) => {}
        Some(AttrValue::Int(_)) => return Err(OnnxError::Unsupported),
        Some(_) => return Err(OnnxError::Graph),
    }
    if !source.attrs.is_empty() || !epsilon.is_finite() || epsilon <= 0.0 {
        return Err(OnnxError::Unsupported);
    }
    let input = lowering
        .known
        .get(&source.inputs[0])
        .ok_or(OnnxError::Graph)?;
    if input.dtype() != DType::F32
        || !(1..=8).contains(&input.rank())
        || input.shape().dims().contains(&0)
    {
        return Err(OnnxError::Unsupported);
    }
    let dims = input.shape().dims().to_vec();
    let rank = dims.len() as i64;
    if !(-rank..rank).contains(&axis) {
        return Err(OnnxError::Graph);
    }
    let axis = if axis < 0 { axis + rank } else { axis } as usize;
    let bias = source
        .inputs
        .get(2)
        .filter(|name| !name.is_empty())
        .cloned();
    // ONNX permits unidirectional broadcasting to X, including scalars and
    // runtime scale/bias tensors. A native multidirectional broadcast must not
    // accidentally expand X or introduce a leading dimension.
    for name in std::iter::once(&source.inputs[1]).chain(bias.as_ref()) {
        lowering.admission.charge(1 + dims.len())?;
        let affine = lowering.known.get(name).ok_or(OnnxError::Graph)?;
        if affine.dtype() != DType::F32
            || affine.rank() > dims.len()
            || affine
                .shape()
                .dims()
                .iter()
                .rev()
                .zip(dims.iter().rev())
                .any(|(&from, &to)| from != 1 && from != to)
        {
            return Err(OnnxError::Graph);
        }
    }
    let product = |shape: &[usize]| {
        shape.iter().try_fold(1_usize, |n, &dim| {
            n.checked_mul(dim).ok_or(OnnxError::Limit)
        })
    };
    let rows = product(&dims[..axis])?;
    let width = product(&dims[axis..])?;
    if width == 0 || width > 1 << 24 {
        return Err(OnnxError::Limit);
    }
    let mut output = dims.clone();
    output[axis..].fill(1);
    let flatten = dims != [rows, width];
    let restore = output != [rows, 1];
    let mean_nodes = 2 + usize::from(flatten) + usize::from(restore);
    let nodes = 2 * mean_nodes + 7 + usize::from(bias.is_some());
    let ones_bytes = width.checked_mul(4).ok_or(OnnxError::Limit)?;
    let added_bytes = ones_bytes.checked_add(12).ok_or(OnnxError::Limit)?;
    let limits = lowering.admission.limits;
    // Four shared constants and every helper fit before any large vector or
    // generated name is allocated. Every intermediate is no larger than X.
    if lowering
        .nodes
        .len()
        .checked_add(nodes)
        .ok_or(OnnxError::Limit)?
        > limits.nodes
        || lowering
            .known
            .len()
            .checked_add(nodes + 4)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
        || lowering
            .reserved
            .len()
            .checked_add(nodes + 3)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
        || lowering
            .parameter_bytes
            .checked_add(added_bytes)
            .ok_or(OnnxError::Limit)?
            > limits.parameter_bytes
        || ones_bytes > limits.tensor_bytes
    {
        return Err(OnnxError::Limit);
    }
    let ones_name = lowering.fresh_name(&format!("{}-layernorm-ones", source.id))?;
    let ones = port(
        ones_name.clone(),
        vec![width, 1],
        lowering.generation,
        lowering.admission,
    )?;
    lowering.admission.charge(ones_bytes)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(width)
        .map_err(|_| OnnxError::Limit)?;
    for _ in 0..width {
        lowering.admission.charge(1)?;
        values.push(1.0_f32);
    }
    lowering.admission.charge(ones_bytes)?;
    let tensor = Tensor::from_values(ones.shape().clone(), &values, lowering.generation)
        .map_err(|_| OnnxError::Limit)?;
    lowering.add_constant(ones, tensor)?;
    let divisor = scalar(&source, lowering, "width", width as f32)?;
    let epsilon = scalar(&source, lowering, "epsilon", epsilon)?;
    let one = scalar(&source, lowering, "one", 1.0)?;
    let reduction = Reduction {
        matrix: [rows, width],
        output,
        flatten,
        restore,
        ones: ones_name,
        divisor,
    };
    let average = mean(
        &source,
        lowering,
        &reduction,
        source.inputs[0].clone(),
        "mean",
    )?;
    let deviation = append(
        &source,
        lowering,
        Some("center"),
        OpCode::Sub,
        vec![source.inputs[0].clone(), average],
        AttributeMap::new(),
    )?;
    let squared = append(
        &source,
        lowering,
        Some("square"),
        OpCode::Mul,
        vec![deviation.clone(), deviation.clone()],
        AttributeMap::new(),
    )?;
    let variance = mean(&source, lowering, &reduction, squared, "variance")?;
    let stabilized = append(
        &source,
        lowering,
        Some("stabilize"),
        OpCode::Add,
        vec![variance, epsilon],
        AttributeMap::new(),
    )?;
    let deviation_root = append(
        &source,
        lowering,
        Some("sqrt"),
        OpCode::Sqrt,
        vec![stabilized],
        AttributeMap::new(),
    )?;
    let inverse = append(
        &source,
        lowering,
        Some("reciprocal"),
        OpCode::Div,
        vec![one, deviation_root],
        AttributeMap::new(),
    )?;
    let normalized = append(
        &source,
        lowering,
        Some("normalize"),
        OpCode::Mul,
        vec![deviation, inverse],
        AttributeMap::new(),
    )?;
    let scaled = append(
        &source,
        lowering,
        bias.as_ref().map(|_| "scale"),
        OpCode::Mul,
        vec![normalized, source.inputs[1].clone()],
        AttributeMap::new(),
    )?;
    if let Some(bias) = bias {
        append(
            &source,
            lowering,
            None,
            OpCode::Add,
            vec![scaled, bias],
            AttributeMap::new(),
        )?;
    }
    Ok(())
}

#![forbid(unsafe_code)]
//! Bounded Pow-13 lowering for a scalar embedded F32 exponent of exactly 2 or 3.
//!
//! https://onnx.ai/onnx/operators/onnx__Pow.html#pow-13
//! The admitted arithmetic is `x * x` and `(x * x) * x`, respectively, with
//! native F32 rounding after each multiplication. This is not an arbitrary
//! exponent implementation or a bitwise `powf` equivalence claim. Squaring uses
//! one rounding; cubing uses two, with relative error at most `2u / (1 - 2u)`,
//! `u = 2^-24`, when both products and the exact result are finite and normal. Signed
//! zero, gradual underflow and overflow retain the existing Mul semantics.
//!
//! The source exponent remains charged and retained in original ONNX provenance.
//! A control-only exponent is absent from runtime weights; an exponent also used
//! as runtime data remains bound. No data-dependent or transformed value is frozen.

use fss_tensor::DType;

use super::{Lowering, OnnxError, Result, SourceNode};
use crate::{AttributeMap, GraphNode, OpCode};

pub(super) fn lower(source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    if source.inputs.len() != 2
        || source.outputs.len() != 1
        || source.inputs.iter().any(String::is_empty)
    {
        return Err(OnnxError::Graph);
    }
    if !source.attrs.is_empty() {
        return Err(OnnxError::Unsupported);
    }
    let input = lowering
        .known
        .get(&source.inputs[0])
        .ok_or(OnnxError::Graph)?;
    let exponent = lowering
        .known
        .get(&source.inputs[1])
        .ok_or(OnnxError::Graph)?;
    if input.dtype() != DType::F32
        || input.shape().dims().contains(&0)
        || exponent.dtype() != DType::F32
        || exponent.rank() != 0
    {
        return Err(OnnxError::Unsupported);
    }
    lowering.admission.charge(4)?;
    let constant = lowering
        .constants
        .get(&source.inputs[1])
        .ok_or(OnnxError::Unsupported)?;
    let values = constant.to_vec::<f32>().map_err(|_| OnnxError::Graph)?;
    let count = match values.as_slice() {
        [value] if value.to_bits() == 2.0_f32.to_bits() => 1_usize,
        [value] if value.to_bits() == 3.0_f32.to_bits() => 2_usize,
        _ => return Err(OnnxError::Unsupported),
    };

    // Admit every generated node and tensor before allocating helper names.
    // Both outputs have exactly the already-admitted base shape; no parameter
    // replication or runtime exponent tensor is needed.
    let limits = lowering.admission.limits;
    if lowering
        .nodes
        .len()
        .checked_add(count)
        .ok_or(OnnxError::Limit)?
        > limits.nodes
        || lowering
            .known
            .len()
            .checked_add(count)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
        || lowering
            .reserved
            .len()
            .checked_add(count - 1)
            .ok_or(OnnxError::Limit)?
            > limits.tensors
    {
        return Err(OnnxError::Limit);
    }
    lowering.admission.charge(count)?;
    lowering.control_uses.insert(source.inputs[1].clone());
    let (square_id, square_output) = if count == 1 {
        (source.id.clone(), source.outputs[0].clone())
    } else {
        let id = format!("{}-pow-square", source.id);
        let output = lowering.fresh_name(&id)?;
        (id, output)
    };
    lowering.append(
        GraphNode::new(
            square_id,
            OpCode::Mul,
            source.label.clone(),
            vec![source.inputs[0].clone(), source.inputs[0].clone()],
            vec![square_output.clone()],
            AttributeMap::new(),
        )
        .map_err(|_| OnnxError::Graph)?,
    )?;
    if count == 2 {
        lowering.append(
            GraphNode::new(
                source.id,
                OpCode::Mul,
                source.label,
                vec![square_output, source.inputs[0].clone()],
                source.outputs,
                AttributeMap::new(),
            )
            .map_err(|_| OnnxError::Graph)?,
        )?;
    }
    Ok(())
}

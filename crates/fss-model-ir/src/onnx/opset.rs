#![forbid(unsafe_code)]
//! Explicit schema admission at the three supported default-domain opsets.
//!
//! Schema history: https://onnx.ai/onnx/operators/ . Between 13 and 17 the
//! admitted F32 arithmetic and bounded INT64 controls retain their semantics.
//! Add/Sub/Mul/Div/Relu-14, Pow-15, Identity/Where-16 extend types; LeakyRelu-16
//! adds a function definition with the same admitted finite F32 behavior.
//! Reshape-14 and BatchNormalization-15 introduce mode attributes, which must
//! never be silently interpreted using an earlier schema. Shape-15 adds a
//! bounded metadata slice. LayerNormalization first exists at opset 17.
//! The ONNX operator_sets.h version-18 registration changes only ReduceMean,
//! ReduceL2, Split, Pad and Resize within this closed list. The reduction and
//! partition lowerers receive the original source version. Pad/Resize retain
//! only their earlier numerical subset, including explicit equivalent defaults.

use super::{OnnxError, Result, SourceNode};
use crate::AttrValue;

/// Remove only a schema's explicitly requested legacy-equivalent default.
fn default_mode(source: &mut SourceNode<'_>, name: &str) -> Result<()> {
    match source.attrs.remove(name) {
        None | Some(AttrValue::Int(0)) => Ok(()),
        Some(AttrValue::Int(_)) => Err(OnnxError::Unsupported),
        Some(_) => Err(OnnxError::Graph),
    }
}

pub(super) fn admit(version: u64, source: &mut SourceNode<'_>) -> Result<()> {
    if version == 13 {
        // Preserve the original profile and bytes. Shape-13 has no start/end
        // attributes; LayerNormalization is not an operator in this opset.
        return if source.op == "LayerNormalization"
            || (source.op == "Shape" && !source.attrs.is_empty())
        {
            Err(OnnxError::Unsupported)
        } else {
            Ok(())
        };
    }
    if !matches!(version, 17 | 18) {
        return Err(OnnxError::Unsupported);
    }
    if version == 18 {
        match source.op.as_str() {
            "Resize" => {
                // Resize-18 adds subset axes, antialiasing and aspect policy.
                // Retain the existing nearest/linear spatial resampler only.
                if source.attrs.contains_key("axes") {
                    return Err(OnnxError::Unsupported);
                }
                default_mode(source, "antialias")?;
                match source.attrs.remove("keep_aspect_ratio_policy") {
                    None => {}
                    Some(AttrValue::String(value)) if value == "stretch" => {}
                    Some(AttrValue::String(_)) => return Err(OnnxError::Unsupported),
                    Some(_) => return Err(OnnxError::Graph),
                }
            }
            _ => {}
        }
    }
    match source.op.as_str() {
        "Reshape" => default_mode(source, "allowzero"),
        "BatchNormalization" => default_mode(source, "training_mode"),
        // This closed list requires an explicit schema audit whenever another
        // source operator is added. Its existing lowerer still checks every
        // attribute, input, dtype, shape and numerical restriction.
        "Add"
        | "Sub"
        | "Mul"
        | "Div"
        | "Relu"
        | "Sigmoid"
        | "Tanh"
        | "Sqrt"
        | "Erf"
        | "MatMul"
        | "Softmax"
        | "Conv"
        | "MaxPool"
        | "Transpose"
        | "Concat"
        | "Identity"
        | "Flatten"
        | "Constant"
        | "Gather"
        | "Shape"
        | "ConstantOfShape"
        | "Equal"
        | "Where"
        | "Gemm"
        | "ConvTranspose"
        | "InstanceNormalization"
        | "LayerNormalization"
        | "HardSigmoid"
        | "Clip"
        | "LeakyRelu"
        | "Pow"
        | "Expand"
        | "Tile"
        | "ReduceMean"
        | "ReduceSum"
        | "ReduceL2"
        | "AveragePool"
        | "GlobalAveragePool"
        | "Resize"
        | "Pad"
        | "Split"
        | "DepthToSpace"
        | "SpaceToDepth"
        | "Squeeze"
        | "Unsqueeze"
        | "Slice" => Ok(()),
        _ => Err(OnnxError::Unsupported),
    }
}

#![forbid(unsafe_code)]
//! Freeze ONNX automatic spatial padding into the existing explicit native pads.
//!
//! Conv-11, MaxPool-12 and AveragePool-11 (selected by opset 13) use the same
//! SAME_UPPER/SAME_LOWER split for positive static spatial dimensions. No image
//! allocation or runtime shape calculation is needed for this conversion.

use super::{OnnxError, Result};
use crate::{AttrValue, AttributeMap};

/// Read a positive pair without consuming it: the native operator still validates
/// and retains the original stride/dilation attribute in its canonical graph.
pub(super) fn pair(attrs: &AttributeMap, key: &str, default: [usize; 2]) -> Result<[usize; 2]> {
    match attrs.get(key) {
        None => Ok(default),
        Some(AttrValue::IntList(values)) if values.len() == 2 => {
            let mut result = [0; 2];
            for (target, value) in result.iter_mut().zip(values) {
                *target = usize::try_from(*value).map_err(|_| OnnxError::Graph)?;
                if *target == 0 {
                    return Err(OnnxError::Graph);
                }
            }
            Ok(result)
        }
        Some(_) => Err(OnnxError::Graph),
    }
}

/// Remove `auto_pad` and replace a non-NOTSET mode with exact explicit pads.
/// Existing NOTSET/explicit-pad graphs keep their original native representation.
pub(super) fn resolve(
    attrs: &mut AttributeMap,
    input: [usize; 2],
    kernel: [usize; 2],
    strides: [usize; 2],
    dilations: [usize; 2],
) -> Result<()> {
    let mode = match attrs.remove("auto_pad") {
        None => return Ok(()),
        Some(AttrValue::String(mode)) if mode == "NOTSET" => return Ok(()),
        Some(AttrValue::String(mode)) => mode,
        Some(_) => return Err(OnnxError::Graph),
    };
    if !matches!(mode.as_str(), "VALID" | "SAME_UPPER" | "SAME_LOWER") {
        return Err(OnnxError::Unsupported);
    }
    // Even all-zero explicit pads are ambiguous with an automatic mode. Do not
    // silently choose one declaration over the other.
    if attrs.contains_key("pads")
        || input.contains(&0)
        || kernel.contains(&0)
        || strides.contains(&0)
        || dilations.contains(&0)
    {
        return Err(OnnxError::Graph);
    }
    let mut pads = [0_i64; 4];
    if mode != "VALID" {
        for axis in 0..2 {
            let effective = (kernel[axis] - 1)
                .checked_mul(dilations[axis])
                .and_then(|n| n.checked_add(1))
                .ok_or(OnnxError::Limit)?;
            // (output - 1) = floor((input - 1) / stride), without overflowing
            // input + stride - 1. A stride wider than the kernel can need no pads.
            let extent = ((input[axis] - 1) / strides[axis])
                .checked_mul(strides[axis])
                .and_then(|n| n.checked_add(effective))
                .ok_or(OnnxError::Limit)?;
            let total = extent.saturating_sub(input[axis]);
            let before = total / 2 + usize::from(mode == "SAME_LOWER") * (total % 2);
            pads[axis] = i64::try_from(before).map_err(|_| OnnxError::Limit)?;
            pads[axis + 2] = i64::try_from(total - before).map_err(|_| OnnxError::Limit)?;
        }
    }
    attrs.insert("pads".into(), AttrValue::IntList(pads.to_vec()));
    Ok(())
}

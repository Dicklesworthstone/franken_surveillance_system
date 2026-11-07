#![forbid(unsafe_code)]
//! Static ONNX Resize-13 nearest-neighbor and linear spatial resampling.
//!
//! https://onnx.ai/onnx/operators/onnx__Resize.html#resize-13
//! Source scales retain their exact F32 value; sizes define an exact ratio.
//! Nearest selection uses existing Slice/Concat operators without arithmetic on
//! image values. Linear interpolation adds bounded one-dimensional coefficients
//! and native Mul/Add. The original integer nearest lowering is unchanged.

use super::resize_coordinates::{
    AxisPlan, CoordinateError, Coordinates, PlanningError, Run, Scale, plan_axis,
};
use super::resize_linear_coordinates::LinearCoordinates;
use super::{Lowering, OnnxError, Result, SourceNode};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

impl From<CoordinateError> for OnnxError {
    fn from(error: CoordinateError) -> Self {
        match error {
            CoordinateError::Limit => Self::Limit,
            CoordinateError::Unsupported => Self::Unsupported,
        }
    }
}

fn text_attribute(attrs: &mut AttributeMap, name: &str, default: &str) -> Result<String> {
    match attrs.remove(name) {
        None => Ok(default.to_owned()),
        Some(AttrValue::String(value)) => Ok(value),
        Some(_) => Err(OnnxError::Graph),
    }
}

enum Interpolation {
    Nearest(Coordinates),
    Linear(LinearCoordinates),
}

fn attributes(attrs: &mut AttributeMap) -> Result<Interpolation> {
    let mode = text_attribute(attrs, "mode", "nearest")?;
    let coordinates = text_attribute(attrs, "coordinate_transformation_mode", "half_pixel")?;
    let nearest = text_attribute(attrs, "nearest_mode", "round_prefer_floor")?;
    let interpolation = match mode.as_str() {
        "nearest" => Interpolation::Nearest(match (coordinates.as_str(), nearest.as_str()) {
            ("asymmetric", "floor") => Coordinates::AsymmetricFloor,
            ("half_pixel", "round_prefer_floor") => Coordinates::HalfPixelRoundPreferFloor,
            _ => return Err(OnnxError::Unsupported),
        }),
        "linear" => {
            // nearest_mode has no numerical effect in linear interpolation;
            // validate even an unused exporter-emitted attribute against its enum.
            if !matches!(
                nearest.as_str(),
                "round_prefer_floor" | "round_prefer_ceil" | "floor" | "ceil"
            ) {
                return Err(OnnxError::Unsupported);
            }
            Interpolation::Linear(match coordinates.as_str() {
                "half_pixel" => LinearCoordinates::HalfPixel,
                "pytorch_half_pixel" => LinearCoordinates::PytorchHalfPixel,
                "align_corners" => LinearCoordinates::AlignCorners,
                "asymmetric" => LinearCoordinates::Asymmetric,
                _ => return Err(OnnxError::Unsupported),
            })
        }
        _ => return Err(OnnxError::Unsupported),
    };
    match attrs.remove("exclude_outside") {
        None | Some(AttrValue::Int(0)) => {}
        Some(AttrValue::Int(_)) => return Err(OnnxError::Unsupported),
        Some(_) => return Err(OnnxError::Graph),
    }
    // These attributes do not affect either admitted interpolation mode. Validate
    // their source types, rather than letting exporter-emitted defaults fail.
    for name in ["cubic_coeff_a", "extrapolation_value"] {
        match attrs.remove(name) {
            None => {}
            Some(AttrValue::Float(value)) if value.is_finite() => {}
            Some(_) => return Err(OnnxError::Graph),
        }
    }
    if !attrs.is_empty() {
        return Err(OnnxError::Unsupported);
    }
    Ok(interpolation)
}

fn reshape(
    lowering: &mut Lowering<'_, '_>,
    id: &str,
    label: &str,
    input: String,
    output: String,
    shape: &[usize],
) -> Result<()> {
    let shape = shape
        .iter()
        .map(|&n| i64::try_from(n).map_err(|_| OnnxError::Limit))
        .collect::<Result<Vec<_>>>()?;
    lowering.append(
        GraphNode::new(
            id,
            OpCode::Reshape,
            label,
            vec![input],
            vec![output],
            AttributeMap::from([("shape".into(), AttrValue::IntList(shape))]),
        )
        .map_err(|_| OnnxError::Graph)?,
    )
}

fn repeat(
    lowering: &mut Lowering<'_, '_>,
    id: &str,
    label: &str,
    input: String,
    output: String,
    axis: i64,
    factor: usize,
) -> Result<()> {
    lowering.admission.charge(factor)?;
    lowering.append(
        GraphNode::new(
            id,
            OpCode::Concat,
            label,
            vec![input; factor],
            vec![output],
            AttributeMap::from([("axis".into(), AttrValue::Int(axis))]),
        )
        .map_err(|_| OnnxError::Graph)?,
    )
}

fn select_axis(
    lowering: &mut Lowering<'_, '_>,
    source: &SourceNode<'_>,
    input: String,
    output: String,
    axis: usize,
    runs: Vec<Run>,
) -> Result<()> {
    let multiple = runs.len() > 1;
    let mut parts = Vec::new();
    parts
        .try_reserve(runs.len())
        .map_err(|_| OnnxError::Limit)?;
    for (index, run) in runs.into_iter().enumerate() {
        let base = format!("{}-resize-axis-{axis}-{index}", source.id);
        let selected = if multiple || run.repetitions > 1 {
            lowering.fresh_name(&format!("{base}-slice"))?
        } else {
            output.clone()
        };
        let integer = |value| i64::try_from(value).map_err(|_| OnnxError::Limit);
        let attrs = AttributeMap::from([
            (
                "starts".into(),
                AttrValue::IntList(vec![integer(run.start)?]),
            ),
            ("ends".into(), AttrValue::IntList(vec![integer(run.end)?])),
            ("axes".into(), AttrValue::IntList(vec![integer(axis)?])),
            ("steps".into(), AttrValue::IntList(vec![integer(run.step)?])),
        ]);
        lowering.append(
            GraphNode::new(
                format!("{base}-slice"),
                OpCode::Slice,
                source.label.clone(),
                vec![input.clone()],
                vec![selected.clone()],
                attrs,
            )
            .map_err(|_| OnnxError::Graph)?,
        )?;
        if run.repetitions > 1 {
            let repeated = if multiple {
                lowering.fresh_name(&format!("{base}-repeat"))?
            } else {
                output.clone()
            };
            repeat(
                lowering,
                &format!("{base}-repeat"),
                &source.label,
                selected,
                repeated.clone(),
                axis as i64,
                run.repetitions,
            )?;
            parts.push(repeated);
        } else {
            parts.push(selected);
        }
    }
    if multiple {
        lowering.append(
            GraphNode::new(
                format!("{}-resize-axis-{axis}-join", source.id),
                OpCode::Concat,
                source.label.clone(),
                parts,
                vec![output],
                AttributeMap::from([("axis".into(), AttrValue::Int(axis as i64))]),
            )
            .map_err(|_| OnnxError::Graph)?,
        )?;
    }
    Ok(())
}

fn repeat_axis(
    lowering: &mut Lowering<'_, '_>,
    source: &SourceNode<'_>,
    input: String,
    output: String,
    dims: [usize; 4],
    axis: usize,
    factor: usize,
) -> Result<()> {
    let base = format!("{}-resize-axis-{axis}", source.id);
    let unit = lowering.fresh_name(&format!("{base}-unit"))?;
    let repeated = lowering.fresh_name(&format!("{base}-repeat"))?;
    let mut unit_shape = dims.to_vec();
    unit_shape.insert(axis + 1, 1);
    reshape(
        lowering,
        &format!("{base}-unit"),
        &source.label,
        input,
        unit.clone(),
        &unit_shape,
    )?;
    repeat(
        lowering,
        &format!("{base}-repeat"),
        &source.label,
        unit,
        repeated.clone(),
        (axis + 1) as i64,
        factor,
    )?;
    let mut output_shape = dims;
    output_shape[axis] = dims[axis].checked_mul(factor).ok_or(OnnxError::Limit)?;
    reshape(
        lowering,
        &format!("{base}-shape"),
        &source.label,
        repeated,
        output,
        &output_shape,
    )
}

fn resample(
    source: &SourceNode<'_>,
    lowering: &mut Lowering<'_, '_>,
    mut dims: [usize; 4],
    scales: [Scale; 2],
    coordinates: Coordinates,
) -> Result<()> {
    // Shrink before enlarging another axis, so mixed-direction resizing does
    // not allocate an intermediate larger than both the input and output.
    let order = if scales[0].output < dims[2] && scales[1].output >= dims[3] {
        [2, 3]
    } else {
        [3, 2]
    };
    let mut plans = Vec::new();
    for axis in order {
        let plan = plan_axis(
            dims[axis],
            scales[axis - 2],
            coordinates,
            lowering.admission.limits.nodes,
            |units| lowering.admission.charge(units),
        )
        .map_err(|error| match error {
            PlanningError::Coordinates(error) => OnnxError::from(error),
            PlanningError::Admission(error) => error,
        })?;
        if !matches!(plan, AxisPlan::Identity) {
            plans.push((axis, plan));
        }
    }
    let nodes = plans
        .iter()
        .map(|(_, plan)| plan.node_count())
        .sum::<usize>();
    if lowering
        .nodes
        .len()
        .checked_add(nodes)
        .ok_or(OnnxError::Limit)?
        > lowering.admission.limits.nodes
        || lowering
            .known
            .len()
            .checked_add(nodes)
            .ok_or(OnnxError::Limit)?
            > lowering.admission.limits.tensors
    {
        return Err(OnnxError::Limit);
    }
    lowering.admission.charge(nodes)?;
    let count = plans.len();
    let mut input = source.inputs[0].clone();
    for (position, (axis, plan)) in plans.into_iter().enumerate() {
        let output = if position + 1 == count {
            source.outputs[0].clone()
        } else {
            lowering.fresh_name(&format!("{}-resize-axis-{axis}", source.id))?
        };
        match plan {
            AxisPlan::Repeat(factor) => {
                repeat_axis(lowering, source, input, output.clone(), dims, axis, factor)?;
            }
            AxisPlan::Select(runs) => {
                select_axis(lowering, source, input, output.clone(), axis, runs)?;
            }
            AxisPlan::Identity => return Err(OnnxError::Graph),
        }
        dims[axis] = scales[axis - 2].output;
        input = output;
    }
    Ok(())
}

pub(super) fn lower(mut source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    if !(3..=4).contains(&source.inputs.len())
        || source.outputs.len() != 1
        || source.inputs[0].is_empty()
    {
        return Err(OnnxError::Graph);
    }
    let interpolation = attributes(&mut source.attrs)?;
    let input = lowering
        .known
        .get(&source.inputs[0])
        .ok_or(OnnxError::Graph)?;
    let dims: [usize; 4] = input
        .shape()
        .dims()
        .try_into()
        .map_err(|_| OnnxError::Unsupported)?;
    if !source.inputs[1].is_empty() && !lowering.constant_f32_vector(&source.inputs[1])?.is_empty()
    {
        return Err(OnnxError::Unsupported);
    }
    let scales = if source.inputs[2].is_empty() {
        Vec::new()
    } else {
        lowering.constant_f32_vector(&source.inputs[2])?
    };
    let sizes = if let Some(name) = source.inputs.get(3).filter(|name| !name.is_empty()) {
        lowering.constant_i64_vector(name)?
    } else {
        Vec::new()
    };
    // Empty optional constant tensors, emitted by several ONNX exporters, are
    // control values only. They must never become zero-sized runtime tensors.
    if scales.is_empty() == sizes.is_empty() {
        return Err(OnnxError::Graph);
    }
    let scales = if !scales.is_empty() {
        if scales.len() != 4 || scales[0] != 1.0 || scales[1] != 1.0 {
            return Err(OnnxError::Unsupported);
        }
        [
            Scale::from_f32(scales[2], dims[2])?,
            Scale::from_f32(scales[3], dims[3])?,
        ]
    } else {
        if sizes.len() != 4 {
            return Err(OnnxError::Graph);
        }
        let mut requested = [0_usize; 4];
        for (target, value) in requested.iter_mut().zip(sizes) {
            *target = usize::try_from(value).map_err(|_| OnnxError::Unsupported)?;
        }
        if requested[..2] != dims[..2] {
            return Err(OnnxError::Unsupported);
        }
        [
            Scale::from_size(requested[2], dims[2])?,
            Scale::from_size(requested[3], dims[3])?,
        ]
    };
    let output_shape = [dims[0], dims[1], scales[0].output, scales[1].output];
    let bytes = output_shape.iter().try_fold(4_usize, |bytes, &dim| {
        bytes.checked_mul(dim).ok_or(OnnxError::Limit)
    })?;
    if bytes > lowering.admission.limits.tensor_bytes {
        return Err(OnnxError::Limit);
    }
    let coordinates = match interpolation {
        Interpolation::Nearest(coordinates) => coordinates,
        Interpolation::Linear(coordinates) => {
            return super::resize_linear::lower(&source, lowering, dims, scales, coordinates);
        }
    };
    let factors = match (scales[0].integer_factor(), scales[1].integer_factor()) {
        (Some(height), Some(width)) => [height, width],
        _ => return resample(&source, lowering, dims, scales, coordinates),
    };
    // Preserve the exact original helper sequence, names and canonical graph
    // for every previously admitted integer scale/size model.
    // Every generated name is reserved against all source names, including
    // future source values. Every emitted node uses the same quota admission.
    let base = format!("{}-resize", source.id);
    let unit = lowering.fresh_name(&format!("{base}-unit"))?;
    let wide = lowering.fresh_name(&format!("{base}-wide"))?;
    let tall = lowering.fresh_name(&format!("{base}-tall"))?;
    reshape(
        lowering,
        &format!("{}-unit", source.id),
        &source.label,
        source.inputs[0].clone(),
        unit.clone(),
        &[dims[0], dims[1], dims[2], 1, dims[3], 1],
    )?;
    repeat(
        lowering,
        &format!("{}-width", source.id),
        &source.label,
        unit,
        wide.clone(),
        5,
        factors[1],
    )?;
    repeat(
        lowering,
        &format!("{}-height", source.id),
        &source.label,
        wide,
        tall.clone(),
        3,
        factors[0],
    )?;
    reshape(
        lowering,
        &source.id,
        &source.label,
        tall,
        source.outputs[0].clone(),
        &output_shape,
    )
}

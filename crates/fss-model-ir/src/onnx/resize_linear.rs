#![forbid(unsafe_code)]
//! Separable Resize-13 linear interpolation through existing native operators.
//!
//! Slice/Concat selections and broadcast one-dimensional coefficient vectors
//! keep storage linear in output-axis lengths. Fractional positions use two
//! separate F32 multiplies followed by addition. A shrinking axis runs first
//! in a mixed resize; otherwise width runs before height.

use fss_tensor::Tensor;

use super::resize_coordinates::{PlanningError, Scale};
use super::resize_linear_coordinates::{
    AxisPlan, Direct, LinearCoordinates, Selection, plan_axis,
};
use super::{Lowering, OnnxError, Result, SourceNode, port};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

struct Emitter<'s, 'a, 'c> {
    source: &'s SourceNode<'s>,
    lowering: &'s mut Lowering<'a, 'c>,
    remaining: usize,
}
impl Emitter<'_, '_, '_> {
    fn append(&mut self, op: OpCode, inputs: Vec<String>, attrs: AttributeMap) -> Result<String> {
        let ordinal = self.remaining;
        self.remaining = self.remaining.checked_sub(1).ok_or(OnnxError::Graph)?;
        let id = if self.remaining == 0 {
            self.source.id.clone()
        } else {
            format!("{}-linear-{ordinal}", self.source.id)
        };
        let output = if self.remaining == 0 {
            self.source.outputs[0].clone()
        } else {
            self.lowering.fresh_name(&id)?
        };
        self.lowering.append(
            GraphNode::new(
                id, op, self.source.label.clone(), inputs, vec![output.clone()], attrs,
            ).map_err(|_| OnnxError::Graph)?,
        )?;
        Ok(output)
    }

    fn reshape(&mut self, input: String, shape: &[usize]) -> Result<String> {
        let shape = shape.iter()
            .map(|&dim| i64::try_from(dim).map_err(|_| OnnxError::Limit))
            .collect::<Result<Vec<_>>>()?;
        self.append(
            OpCode::Reshape,
            vec![input],
            AttributeMap::from([("shape".into(), AttrValue::IntList(shape))]),
        )
    }

    fn concat(&mut self, inputs: Vec<String>, axis: usize) -> Result<String> {
        self.append(
            OpCode::Concat,
            inputs,
            AttributeMap::from([("axis".into(), AttrValue::Int(axis as i64))]),
        )
    }

    fn repeat(&mut self, input: String, axis: usize, repetitions: usize) -> Result<String> {
        self.lowering.admission.charge(repetitions)?;
        let mut inputs = Vec::new();
        inputs.try_reserve_exact(repetitions).map_err(|_| OnnxError::Limit)?;
        inputs.resize_with(repetitions, || input.clone());
        self.concat(inputs, axis)
    }

    fn direct(
        &mut self,
        plan: &Direct,
        input: &str,
        dims: [usize; 4],
        axis: usize,
    ) -> Result<String> {
        if plan.runs.is_empty() {
            return Ok(input.to_owned());
        }
        let mut parts = Vec::new();
        parts.try_reserve_exact(plan.runs.len()).map_err(|_| OnnxError::Limit)?;
        for run in &plan.runs {
            let integer = |n| i64::try_from(n).map_err(|_| OnnxError::Limit);
            let mut selected = self.append(
                OpCode::Slice,
                vec![input.to_owned()],
                AttributeMap::from([
                    ("starts".into(), AttrValue::IntList(vec![integer(run.start)?])),
                    ("ends".into(), AttrValue::IntList(vec![integer(run.end)?])),
                    ("axes".into(), AttrValue::IntList(vec![axis as i64])),
                    ("steps".into(), AttrValue::IntList(vec![integer(run.step)?])),
                ]),
            )?;
            if run.repetitions > 1 {
                if run.count == 1 {
                    selected = self.repeat(selected, axis, run.repetitions)?;
                } else {
                    let mut shape = dims.to_vec();
                    shape[axis] = run.count;
                    shape.insert(axis + 1, 1);
                    selected = self.reshape(selected, &shape)?;
                    selected = self.repeat(selected, axis + 1, run.repetitions)?;
                    let mut shape = dims;
                    shape[axis] = run.count.checked_mul(run.repetitions).ok_or(OnnxError::Limit)?;
                    selected = self.reshape(selected, &shape)?;
                }
            }
            parts.push(selected);
        }
        if parts.len() == 1 {
            parts.pop().ok_or(OnnxError::Graph)
        } else {
            self.concat(parts, axis)
        }
    }

    fn selection(
        &mut self,
        plan: &Selection,
        input: &str,
        dims: [usize; 4],
        axis: usize,
    ) -> Result<String> {
        match plan {
            Selection::Direct(plan) => self.direct(plan, input, dims, axis),
            Selection::Interleave { phases, width, tail } => {
                let mut parts = Vec::new();
                parts.try_reserve_exact(phases.len()).map_err(|_| OnnxError::Limit)?;
                for phase in phases {
                    if phase.output != *width {
                        return Err(OnnxError::Graph);
                    }
                    let selected = self.direct(phase, input, dims, axis)?;
                    let mut shape = dims.to_vec();
                    shape[axis] = *width;
                    shape.insert(axis + 1, 1);
                    parts.push(self.reshape(selected, &shape)?);
                }
                let combined = self.concat(parts, axis + 1)?;
                let mut shape = dims;
                shape[axis] = width.checked_mul(phases.len()).ok_or(OnnxError::Limit)?;
                let prefix = self.reshape(combined, &shape)?;
                if let Some(tail) = tail {
                    let tail = self.direct(tail, input, dims, axis)?;
                    self.concat(vec![prefix, tail], axis)
                } else {
                    Ok(prefix)
                }
            }
        }
    }

    fn weights(&mut self, plan: &AxisPlan, axis: usize) -> Result<[String; 2]> {
        if plan.weights.len() != plan.output {
            return Err(OnnxError::Graph);
        }
        let bytes = plan.output.checked_mul(4).ok_or(OnnxError::Limit)?;
        let mut names = [String::new(), String::new()];
        for (component, name) in names.iter_mut().enumerate() {
            *name = self.lowering.fresh_name(
                &format!("{}-linear-axis-{axis}-weight-{component}", self.source.id),
            )?;
            let mut shape = vec![1; 4];
            shape[axis] = plan.output;
            let port = port(
                name.clone(), shape, self.lowering.generation, self.lowering.admission,
            )?;
            self.lowering.admission.charge(bytes)?;
            let mut values = Vec::new();
            values.try_reserve_exact(plan.output).map_err(|_| OnnxError::Limit)?;
            for weights in &plan.weights {
                self.lowering.admission.charge(1)?;
                values.push(weights[component]);
            }
            self.lowering.admission.charge(bytes)?;
            let tensor = Tensor::from_values(port.shape().clone(), &values, self.lowering.generation)
                .map_err(|_| OnnxError::Limit)?;
            self.lowering.add_constant(port, tensor)?;
        }
        Ok(names)
    }
}

pub(super) fn lower(
    source: &SourceNode<'_>,
    lowering: &mut Lowering<'_, '_>,
    mut dims: [usize; 4],
    scales: [Scale; 2],
    coordinates: LinearCoordinates,
) -> Result<()> {
    // Intermediate spatial area never exceeds max(input_area, output_area).
    // This order is frozen even when another order would round differently.
    let order = if scales[0].output < dims[2] && scales[1].output >= dims[3] {
        [2, 3]
    } else {
        [3, 2]
    };
    let mut plans = Vec::new();
    for axis in order {
        let plan = plan_axis(
            dims[axis], scales[axis - 2], coordinates, lowering.admission.limits.nodes,
            |units| lowering.admission.charge(units),
        ).map_err(|error| match error {
            PlanningError::Coordinates(error) => OnnxError::from(error),
            PlanningError::Admission(error) => error,
        })?;
        if plan.node_count() != 0 {
            plans.push((axis, plan));
        }
    }
    let nodes = plans.iter().map(|(_, plan)| plan.node_count()).sum::<usize>().max(1);
    let parameters = plans.iter().filter(|(_, plan)| plan.upper.is_some()).count() * 2;
    let bytes = plans.iter().map(|(_, plan)| plan.parameter_bytes()).sum::<usize>();
    let limits = lowering.admission.limits;
    // Planning scratch is bounded to 4096 coordinates per axis. Admit the
    // complete graph and coefficients before constructing names or tensors.
    if lowering.nodes.len().checked_add(nodes).ok_or(OnnxError::Limit)? > limits.nodes
        || lowering.known.len().checked_add(nodes + parameters).ok_or(OnnxError::Limit)? > limits.tensors
        || lowering.reserved.len().checked_add(nodes - 1 + parameters).ok_or(OnnxError::Limit)? > limits.tensors
        || lowering.parameter_bytes.checked_add(bytes).ok_or(OnnxError::Limit)? > limits.parameter_bytes
    {
        return Err(OnnxError::Limit);
    }
    lowering.admission.charge(nodes + parameters)?;
    let mut emitter = Emitter { source, lowering, remaining: nodes };
    let mut value = source.inputs[0].clone();
    if plans.is_empty() {
        emitter.reshape(value, &dims)?;
    } else {
        for (axis, plan) in plans {
            let selected = emitter.selection(&plan.lower, &value, dims, axis)?;
            value = if let Some(upper) = &plan.upper {
                let high = emitter.selection(upper, &value, dims, axis)?;
                let [low_weight, high_weight] = emitter.weights(&plan, axis)?;
                let low = emitter.append(OpCode::Mul, vec![selected, low_weight], AttributeMap::new())?;
                let high = emitter.append(OpCode::Mul, vec![high, high_weight], AttributeMap::new())?;
                emitter.append(OpCode::Add, vec![low, high], AttributeMap::new())?
            } else {
                selected
            };
            dims[axis] = plan.output;
        }
    }
    if emitter.remaining != 0 {
        return Err(OnnxError::Graph);
    }
    Ok(())
}

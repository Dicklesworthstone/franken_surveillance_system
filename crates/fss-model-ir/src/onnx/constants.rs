#![forbid(unsafe_code)]
//! Exact embedded constants. Integer and empty tensors are compile-time controls,
//! never runtime Model IR ports or exported F32 model parameters.

use fss_core::Generation;
use fss_tensor::{DType, Shape, Tensor};

use super::{
    Admission, Lowering, OnnxError, Result, SourceNode, Value, Wire, integers, name, push,
    singular, text,
};
use crate::TensorPort;

fn floats(value: Value<'_>, output: &mut Vec<f32>, a: &mut Admission<'_>) -> Result<()> {
    let maximum = a.limits.parameter_bytes / 4;
    match value {
        Value::Fixed32(bits) => {
            a.charge(4)?;
            push(output, f32::from_bits(bits), maximum)
        }
        Value::Bytes(bytes) => {
            if bytes.len() % 4 != 0 {
                return Err(OnnxError::Malformed);
            }
            for bytes in bytes.as_chunks::<4>().0 {
                a.charge(4)?;
                push(output, f32::from_le_bytes(*bytes), maximum)?;
            }
            Ok(())
        }
        _ => Err(OnnxError::Malformed),
    }
}

fn finish(
    id: String,
    dims: Vec<i64>,
    float_values: Option<Vec<f32>>,
    integer_values: Option<Vec<i64>>,
    generation: Generation,
    a: &mut Admission<'_>,
) -> Result<(TensorPort, Tensor)> {
    if dims.len() > 8 || dims.iter().any(|n| *n < 0) {
        return Err(OnnxError::Unsupported);
    }
    let dims = dims
        .into_iter()
        .map(|n| usize::try_from(n).map_err(|_| OnnxError::Limit))
        .collect::<Result<Vec<_>>>()?;
    // Empty controls are one-dimensional vectors. Runtime tensors remain positive.
    if dims.contains(&0) && dims != [0] {
        return Err(OnnxError::Unsupported);
    }
    let shape = Shape::new(dims).map_err(|_| OnnxError::Limit)?;
    let dtype = if integer_values.is_some() {
        DType::I64
    } else {
        DType::F32
    };
    let size = shape.size_bytes(dtype).map_err(|_| OnnxError::Limit)?;
    if size > a.limits.parameter_bytes || size > a.limits.tensor_bytes {
        return Err(OnnxError::Limit);
    }
    let count = shape.num_elements().map_err(|_| OnnxError::Limit)?;
    a.charge(size)?;
    let tensor = match (float_values, integer_values) {
        (Some(values), None) => {
            if values.len() != count {
                return Err(OnnxError::Malformed);
            }
            if values.iter().any(|n| !n.is_finite()) {
                return Err(OnnxError::NonFinite);
            }
            Tensor::from_values(shape.clone(), &values, generation)
        }
        (None, Some(values)) => {
            if shape.rank() > 1 || count > 8 {
                return Err(OnnxError::Unsupported);
            }
            if values.len() != count {
                return Err(OnnxError::Malformed);
            }
            Tensor::from_values(shape.clone(), &values, generation)
        }
        _ => return Err(OnnxError::Malformed),
    }
    .map_err(|_| OnnxError::Limit)?;
    let port = TensorPort::new(id, dtype, shape, generation).map_err(|_| OnnxError::Graph)?;
    Ok((port, tensor))
}

/// TensorProto uses the graph initializer's own name, or a Constant node's output
/// name. A TensorProto name inside an attribute is metadata, not a graph binding.
pub(super) fn tensor(
    bytes: &[u8],
    output: Option<&str>,
    generation: Generation,
    a: &mut Admission<'_>,
) -> Result<(TensorPort, Tensor)> {
    let mut wire = Wire(bytes);
    let (mut seen, mut id, mut dtype, mut raw) = (0, None, None, None);
    let (mut dims, mut float_values, mut integer_values) = (Vec::new(), Vec::new(), Vec::new());
    let (mut has_floats, mut has_integers) = (false, false);
    while let Some((tag, value)) = wire.next(a)? {
        match tag {
            1 => integers(value, &mut dims, 8, a)?,
            4 => {
                has_floats = true;
                floats(value, &mut float_values, a)?;
            }
            7 => {
                has_integers = true;
                integers(
                    value,
                    &mut integer_values,
                    (a.limits.parameter_bytes / 8).min(8),
                    a,
                )?;
            }
            2 | 8 | 9 | 12 => {
                singular(&mut seen, tag)?;
                match tag {
                    2 => dtype = Some(value.integer()?),
                    8 => {
                        let bytes = value.bytes()?;
                        if output.is_some() && bytes.is_empty() {
                            id = None;
                        } else {
                            id = Some(name(bytes)?);
                        }
                    }
                    9 => raw = Some(value.bytes()?),
                    12 => {
                        text(value.bytes()?)?;
                    }
                    _ => return Err(OnnxError::Malformed),
                }
            }
            _ => return Err(OnnxError::Unsupported),
        }
    }
    let id = match output {
        Some(output) => output.to_owned(),
        None => id.ok_or(OnnxError::Malformed)?,
    };
    match dtype {
        Some(1) => {
            if has_integers || (raw.is_some() && has_floats) {
                return Err(OnnxError::Malformed);
            }
            if let Some(raw) = raw {
                floats(Value::Bytes(raw), &mut float_values, a)?;
            }
            finish(id, dims, Some(float_values), None, generation, a)
        }
        Some(7) => {
            if has_floats || (raw.is_some() && has_integers) {
                return Err(OnnxError::Malformed);
            }
            if let Some(raw) = raw {
                if raw.len() % 8 != 0 {
                    return Err(OnnxError::Malformed);
                }
                for bytes in raw.as_chunks::<8>().0 {
                    a.charge(8)?;
                    push(
                        &mut integer_values,
                        i64::from_le_bytes(*bytes),
                        (a.limits.parameter_bytes / 8).min(8),
                    )?;
                }
            }
            finish(id, dims, None, Some(integer_values), generation, a)
        }
        _ => Err(OnnxError::Unsupported),
    }
}

fn attribute(
    bytes: &[u8],
    output: &str,
    generation: Generation,
    a: &mut Admission<'_>,
) -> Result<(TensorPort, Tensor)> {
    let mut wire = Wire(bytes);
    let (mut seen, mut id, mut ty, mut embedded) = (0, None, None, None);
    let (mut float_values, mut integer_values) = (Vec::new(), Vec::new());
    let (mut float_list, mut integer_list) = (false, false);
    while let Some((tag, value)) = wire.next(a)? {
        match tag {
            7 => {
                float_list = true;
                floats(value, &mut float_values, a)?;
            }
            8 => {
                integer_list = true;
                integers(
                    value,
                    &mut integer_values,
                    (a.limits.parameter_bytes / 8).min(8),
                    a,
                )?;
            }
            _ => {
                singular(&mut seen, tag)?;
                match tag {
                    1 => id = Some(name(value.bytes()?)?),
                    2 => {
                        if !matches!(value, Value::Fixed32(_)) {
                            return Err(OnnxError::Malformed);
                        }
                        floats(value, &mut float_values, a)?;
                    }
                    3 => {
                        a.charge(8)?;
                        push(
                            &mut integer_values,
                            value.integer()? as i64,
                            (a.limits.parameter_bytes / 8).min(8),
                        )?;
                    }
                    5 => embedded = Some(value.bytes()?),
                    13 => {
                        text(value.bytes()?)?;
                    }
                    20 => ty = Some(value.integer()?),
                    _ => return Err(OnnxError::Unsupported),
                }
            }
        }
    }
    let scalar_float = seen & (1 << 2) != 0;
    let scalar_integer = seen & (1 << 3) != 0;
    let fields = usize::from(scalar_float)
        + usize::from(scalar_integer)
        + usize::from(embedded.is_some())
        + usize::from(float_list)
        + usize::from(integer_list);
    // Empty repeated protobuf fields may be omitted on the wire. The typed
    // attribute still denotes an empty vector, never a scalar/default value.
    if fields == 0 {
        return match (id.as_deref(), ty) {
            (Some("value_floats"), Some(6)) => finish(
                output.into(),
                vec![0],
                Some(Vec::new()),
                None,
                generation,
                a,
            ),
            (Some("value_ints"), Some(7)) => finish(
                output.into(),
                vec![0],
                None,
                Some(Vec::new()),
                generation,
                a,
            ),
            _ => Err(OnnxError::Malformed),
        };
    }
    if fields != 1 {
        return Err(OnnxError::Malformed);
    }
    match (id.as_deref(), ty) {
        (Some("value"), Some(4)) if embedded.is_some() => tensor(
            embedded.ok_or(OnnxError::Malformed)?,
            Some(output),
            generation,
            a,
        ),
        (Some("value_float"), Some(1)) if scalar_float => finish(
            output.into(),
            Vec::new(),
            Some(float_values),
            None,
            generation,
            a,
        ),
        (Some("value_floats"), Some(6)) if float_list => finish(
            output.into(),
            vec![float_values.len() as i64],
            Some(float_values),
            None,
            generation,
            a,
        ),
        (Some("value_int"), Some(2)) if scalar_integer => finish(
            output.into(),
            Vec::new(),
            None,
            Some(integer_values),
            generation,
            a,
        ),
        (Some("value_ints"), Some(7)) if integer_list => finish(
            output.into(),
            vec![integer_values.len() as i64],
            None,
            Some(integer_values),
            generation,
            a,
        ),
        _ => Err(OnnxError::Unsupported),
    }
}

pub(super) fn lower(source: SourceNode<'_>, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    if !source.inputs.is_empty() || source.outputs.len() != 1 || !source.attrs.is_empty() {
        return Err(OnnxError::Graph);
    }
    let maximum = lowering.admission.limits.parameter_bytes;
    lowering.admission.limits.parameter_bytes = maximum.saturating_sub(lowering.parameter_bytes);
    let value = attribute(
        source.constant.ok_or(OnnxError::Malformed)?,
        &source.outputs[0],
        lowering.generation,
        lowering.admission,
    )?;
    lowering.admission.limits.parameter_bytes = maximum;
    lowering.add_constant(value.0, value.1)
}

impl Lowering<'_, '_> {
    pub(super) fn add_constant(&mut self, port: TensorPort, tensor: Tensor) -> Result<()> {
        let size = tensor
            .shape()
            .size_bytes(tensor.dtype())
            .map_err(|_| OnnxError::Limit)?;
        let next = self
            .parameter_bytes
            .checked_add(size)
            .ok_or(OnnxError::Limit)?;
        if next > self.admission.limits.parameter_bytes
            || self.known.len() >= self.admission.limits.tensors
        {
            return Err(OnnxError::Limit);
        }
        let name = port.name().to_owned();
        if self.known.contains_key(&name) || self.constants.contains_key(&name) {
            return Err(OnnxError::Graph);
        }
        if port.dtype() == DType::F32 && !port.shape().dims().contains(&0) {
            push(
                &mut self.inputs,
                port.clone(),
                self.admission.limits.tensors,
            )?;
            self.parameters.insert(name.clone(), tensor.clone());
        }
        self.known.insert(name.clone(), port);
        self.constants.insert(name, tensor);
        self.parameter_bytes = next;
        Ok(())
    }

    fn control_vector(&mut self, name: &str, dtype: DType) -> Result<Tensor> {
        let tensor = self.constants.get(name).ok_or(OnnxError::Unsupported)?;
        if tensor.dtype() != dtype || tensor.shape().rank() != 1 {
            return Err(OnnxError::Graph);
        }
        let count = tensor
            .shape()
            .num_elements()
            .map_err(|_| OnnxError::Limit)?;
        if count > 8 {
            return Err(OnnxError::Limit);
        }
        self.admission.charge(
            count
                .checked_mul(dtype.size_bytes())
                .ok_or(OnnxError::Limit)?,
        )?;
        self.control_uses.insert(name.to_owned());
        Ok(tensor.clone())
    }

    pub(super) fn constant_i64_vector(&mut self, name: &str) -> Result<Vec<i64>> {
        self.control_vector(name, DType::I64)?
            .to_vec::<i64>()
            .map_err(|_| OnnxError::Graph)
    }

    // Resize accepts only exact embedded vectors for its compile-time controls.
    pub(super) fn constant_f32_vector(&mut self, name: &str) -> Result<Vec<f32>> {
        self.control_vector(name, DType::F32)?
            .to_vec::<f32>()
            .map_err(|_| OnnxError::Graph)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttributeMap, GraphNode, OpCode};
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn empty_f32_controls_do_not_become_runtime_model_parameters() -> Result<()> {
        let mut admission = Admission {
            limits: super::super::OnnxLimits::default(),
            used: 0,
            cancelled: &|| false,
        };
        let mut lowering = Lowering {
            admission: &mut admission,
            generation: Generation(1),
            inputs: Vec::new(),
            known: BTreeMap::new(),
            parameters: BTreeMap::new(),
            constants: BTreeMap::new(),
            parameter_bytes: 0,
            used_parameters: BTreeSet::new(),
            control_uses: BTreeSet::new(),
            nodes: Vec::new(),
            reserved: BTreeSet::new(),
        };
        let shape = Shape::new(vec![0]).map_err(|_| OnnxError::Graph)?;
        let port = TensorPort::new("roi", DType::F32, shape.clone(), Generation(1))
            .map_err(|_| OnnxError::Graph)?;
        let tensor = Tensor::from_values(shape, &[] as &[f32], Generation(1))
            .map_err(|_| OnnxError::Graph)?;
        lowering.add_constant(port, tensor)?;
        assert!(lowering.constant_f32_vector("roi")?.is_empty());
        assert!(lowering.control_uses.contains("roi"));
        assert!(lowering.inputs.is_empty());
        assert!(lowering.parameters.is_empty());
        let node = GraphNode::new(
            "identity",
            OpCode::Reshape,
            "empty data forbidden",
            vec!["roi".into()],
            vec!["output".into()],
            AttributeMap::from([("shape".into(), crate::AttrValue::IntList(vec![0]))]),
        )
        .map_err(|_| OnnxError::Graph)?;
        assert_eq!(lowering.append(node), Err(OnnxError::Unsupported));
        Ok(())
    }

    #[test]
    fn empty_repeated_constant_attributes_need_no_wire_payload() -> Result<()> {
        for (wire, dtype) in [
            (
                [&[10, 12][..], b"value_floats", &[160, 1, 6][..]].concat(),
                DType::F32,
            ),
            (
                [&[10, 10][..], b"value_ints", &[160, 1, 7][..]].concat(),
                DType::I64,
            ),
        ] {
            let mut admission = Admission {
                limits: super::super::OnnxLimits::default(),
                used: 0,
                cancelled: &|| false,
            };
            let (port, tensor) = attribute(&wire, "empty", Generation(1), &mut admission)?;
            assert_eq!(port.dtype(), dtype);
            assert_eq!(tensor.shape().dims(), &[0]);
            assert_eq!(
                tensor
                    .shape()
                    .num_elements()
                    .map_err(|_| OnnxError::Graph)?,
                0
            );
        }
        Ok(())
    }
}

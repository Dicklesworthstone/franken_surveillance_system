#![forbid(unsafe_code)]
//! ONNX Gemm-13 lowering using only the frozen native Model IR v1 operators.
//!
//! Contract: https://onnx.ai/onnx/operators/onnx__Gemm.html#gemm-13
//! Multipliers apply after the matrix product / to C respectively. Folding alpha
//! into either matrix changes F32 rounding and intermediate overflow behavior.

use fss_tensor::Tensor;

use super::{Lowering, OnnxError, Result, SourceNode, port, push};
use crate::{AttrValue, AttributeMap, GraphNode, OpCode};

fn multiplier(attrs: &mut AttributeMap, name: &str) -> Result<f32> {
    match attrs.remove(name) {
        None => Ok(1.0),
        Some(AttrValue::Float(value)) if value.is_finite() => Ok(value as f32),
        Some(_) => Err(OnnxError::Graph),
    }
}

fn transpose_flag(attrs: &mut AttributeMap, name: &str) -> Result<bool> {
    match attrs.remove(name) {
        None => Ok(false),
        // ONNX specifies nonzero, including negative/non-one INT values.
        Some(AttrValue::Int(value)) => Ok(value != 0),
        Some(_) => Err(OnnxError::Graph),
    }
}

impl Lowering<'_, '_> {
    fn fresh_name(&mut self, base: &str) -> Result<String> {
        if self.reserved.len() >= self.admission.limits.tensors {
            return Err(OnnxError::Limit);
        }
        // All source and already generated names are reserved. The pigeonhole
        // bound gives a deterministic, finite search even for adversarial names.
        for suffix in 0..=self.reserved.len() {
            self.admission.charge(1)?;
            let candidate = if suffix == 0 {
                base.to_owned()
            } else {
                format!("{base}-{suffix}")
            };
            if self.reserved.insert(candidate.clone()) {
                return Ok(candidate);
            }
        }
        Err(OnnxError::Limit)
    }

    fn scalar(&mut self, base: &str, value: f32) -> Result<String> {
        let limits = self.admission.limits;
        let next = self
            .parameter_bytes
            .checked_add(4)
            .ok_or(OnnxError::Limit)?;
        if next > limits.parameter_bytes || self.known.len() >= limits.tensors {
            return Err(OnnxError::Limit);
        }
        self.admission.charge(4)?;
        let name = self.fresh_name(base)?;
        let port = port(name.clone(), Vec::new(), self.generation, self.admission)?;
        let tensor = Tensor::from_values(port.shape().clone(), &[value], self.generation)
            .map_err(|_| OnnxError::Limit)?;
        push(&mut self.inputs, port.clone(), limits.tensors)?;
        if self.known.insert(name.clone(), port).is_some()
            || self.parameters.insert(name.clone(), tensor).is_some()
        {
            return Err(OnnxError::Graph);
        }
        self.parameter_bytes = next;
        Ok(name)
    }

    fn transpose(&mut self, id: &str, input: String) -> Result<String> {
        let output = self.fresh_name(id)?;
        let attrs = AttributeMap::from([("permutation".into(), AttrValue::IntList(vec![1, 0]))]);
        self.append(
            GraphNode::new(
                id,
                OpCode::Transpose,
                id,
                vec![input],
                vec![output.clone()],
                attrs,
            )
            .map_err(|_| OnnxError::Graph)?,
        )?;
        Ok(output)
    }

    fn binary(
        &mut self,
        id: &str,
        label: &str,
        op: OpCode,
        inputs: [String; 2],
        output: String,
    ) -> Result<()> {
        self.append(
            GraphNode::new(
                id,
                op,
                label,
                inputs.to_vec(),
                vec![output],
                AttributeMap::new(),
            )
            .map_err(|_| OnnxError::Graph)?,
        )
    }
}

pub(super) fn lower(mut source: SourceNode, lowering: &mut Lowering<'_, '_>) -> Result<()> {
    if !(2..=3).contains(&source.inputs.len())
        || source.outputs.len() != 1
        || source.inputs[..2].iter().any(String::is_empty)
    {
        return Err(OnnxError::Graph);
    }
    let alpha = multiplier(&mut source.attrs, "alpha")?;
    let beta = multiplier(&mut source.attrs, "beta")?;
    let trans_a = transpose_flag(&mut source.attrs, "transA")?;
    let trans_b = transpose_flag(&mut source.attrs, "transB")?;
    if !source.attrs.is_empty() {
        return Err(OnnxError::Unsupported);
    }
    let a = lowering
        .known
        .get(&source.inputs[0])
        .ok_or(OnnxError::Graph)?;
    let b = lowering
        .known
        .get(&source.inputs[1])
        .ok_or(OnnxError::Graph)?;
    if a.rank() != 2 || b.rank() != 2 {
        return Err(OnnxError::Unsupported);
    }
    let (m, k) = if trans_a {
        (a.shape().dims()[1], a.shape().dims()[0])
    } else {
        (a.shape().dims()[0], a.shape().dims()[1])
    };
    let (b_k, n) = if trans_b {
        (b.shape().dims()[1], b.shape().dims()[0])
    } else {
        (b.shape().dims()[0], b.shape().dims()[1])
    };
    if k != b_k {
        return Err(OnnxError::Graph);
    }
    let bias = source.inputs.get(2).filter(|name| !name.is_empty());
    if let Some(name) = bias {
        let c = lowering.known.get(name).ok_or(OnnxError::Graph)?;
        // A general Add also permits the *result* to expand. Gemm does not:
        // C may only broadcast into the already fixed [M, N] product shape.
        if c.rank() > 2
            || c.shape()
                .dims()
                .iter()
                .rev()
                .zip([n, m])
                .any(|(&dim, target)| dim != 1 && dim != target)
        {
            return Err(OnnxError::Graph);
        }
    }
    port(
        source.outputs[0].clone(),
        vec![m, n],
        lowering.generation,
        lowering.admission,
    )?;
    let scalar_count = 1 + usize::from(bias.is_some());
    let node_count =
        2 + usize::from(trans_a) + usize::from(trans_b) + 2 * usize::from(bias.is_some());
    let limits = lowering.admission.limits;
    if lowering.nodes.len() + node_count > limits.nodes
        || lowering.reserved.len() + node_count - 1 + scalar_count > limits.tensors
        || lowering.parameter_bytes + 4 * scalar_count > limits.parameter_bytes
    {
        return Err(OnnxError::Limit);
    }

    let mut a = source.inputs[0].clone();
    let mut b = source.inputs[1].clone();
    if trans_a {
        a = lowering.transpose(&format!("{}-gemm-transpose-a", source.id), a)?;
    }
    if trans_b {
        b = lowering.transpose(&format!("{}-gemm-transpose-b", source.id), b)?;
    }
    let product = lowering.fresh_name(&format!("{}-gemm-product", source.id))?;
    lowering.binary(
        &format!("{}-gemm-matmul", source.id),
        &source.label,
        OpCode::MatMul,
        [a, b],
        product.clone(),
    )?;
    let alpha = lowering.scalar(&format!("{}-gemm-alpha", source.id), alpha)?;
    let Some(bias) = bias else {
        // Missing C is the optional zero-bias path. As in ONNX's reference
        // implementation, beta has no execution branch without a bias input.
        return lowering.binary(
            &source.id,
            &source.label,
            OpCode::Mul,
            [product, alpha],
            source.outputs[0].clone(),
        );
    };
    let scaled_product = lowering.fresh_name(&format!("{}-gemm-scaled-product", source.id))?;
    lowering.binary(
        &format!("{}-gemm-scale-product", source.id),
        &source.label,
        OpCode::Mul,
        [product, alpha],
        scaled_product.clone(),
    )?;
    let beta = lowering.scalar(&format!("{}-gemm-beta", source.id), beta)?;
    let scaled_bias = lowering.fresh_name(&format!("{}-gemm-scaled-bias", source.id))?;
    lowering.binary(
        &format!("{}-gemm-scale-bias", source.id),
        &source.label,
        OpCode::Mul,
        [bias.clone(), beta],
        scaled_bias.clone(),
    )?;
    lowering.binary(
        &source.id,
        &source.label,
        OpCode::Add,
        [scaled_product, scaled_bias],
        source.outputs[0].clone(),
    )
}

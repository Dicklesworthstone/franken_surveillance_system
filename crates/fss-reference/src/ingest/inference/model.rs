#![forbid(unsafe_code)]
//! Immutable, digest-pinned inputs for the recorded scalar-executor bridge.

use std::collections::BTreeMap;
use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest};
use fss_model_ir::{ModelIrGraph, decode_canonical_model_ir, encode_canonical_model_ir};
use fss_tensor::{DType, Tensor};
use crate::{ChannelTransform, ExecBudget, PreprocessProgram};
use crate::ingest::recorded_decode::RecordedFrame;
use super::{ModelRunError, Result, MAX_RUN_TENSOR_BYTES};

/// Maximum self-contained graph, preprocessing and parameter object size.
pub const MAX_RECORDED_MODEL_BYTES: usize = 16 * 1024 * 1024;
/// Internal recorded-model format, not a model admission or activation certificate.
pub const RECORDED_MODEL_DOMAIN: &str = "fss.recorded_model.v1";

/// Exact graph and F32 parameters plus explicit full-resolution luma preprocessing.
///
/// This is a local execution input, not production model-registry admission. The caller must
/// separately establish authorization, license/provenance and task-specific calibration.
/// Parameter ports are graph inputs other than the single selected `[1,1,H,W]` image port.
#[derive(Clone, Debug)]
pub struct RecordedModel {
    graph: ModelIrGraph,
    frame_input: String,
    scale_to_unit: bool,
    parameters: BTreeMap<String, Vec<f32>>,
    bytes: Vec<u8>,
    digest: ContentDigest,
}

impl RecordedModel {
    /// Freezes an authored/converted graph and exact parameter values for local execution.
    /// No weights are downloaded, guessed, randomized or filled in for missing ports.
    pub fn publish(
        graph: &ModelIrGraph, frame_input: &str, scale_to_unit: bool,
        parameters: BTreeMap<String, Vec<f32>>,
    ) -> Result<Self> {
        let graph_bytes = encode_canonical_model_ir(graph)?;
        let mut size = graph_bytes.len().checked_add(128 + frame_input.len()).ok_or(ModelRunError::Limit)?;
        for (name, values) in &parameters {
            size = size.checked_add(name.len()).and_then(|n| n.checked_add(16))
                .and_then(|n| values.len().checked_mul(4).and_then(|v| n.checked_add(v)))
                .ok_or(ModelRunError::Limit)?;
        }
        if size > MAX_RECORDED_MODEL_BYTES || parameters.len() > 256 { return Err(ModelRunError::Limit); }
        let mut e = CanonicalEncoder::new();
        e.bytes(b"FSSRMDL1"); e.u32(1); e.text(RECORDED_MODEL_DOMAIN);
        e.digest(ContentDigest::sha256(&graph_bytes)); e.bytes(&graph_bytes);
        e.text(frame_input); e.bool(scale_to_unit); e.u64(parameters.len() as u64);
        for (name, values) in parameters {
            e.text(&name); e.u64(values.len() as u64);
            for value in values {
                if !value.is_finite() { return Err(ModelRunError::NonFinite); }
                e.u32(value.to_bits());
            }
        }
        let bytes = e.finish_checked()?;
        Self::decode(&bytes, ContentDigest::sha256(&bytes))
    }

    /// Loads an exact self-contained object. All parameter lengths are checked before allocation.
    pub fn decode(bytes: &[u8], expected: ContentDigest) -> Result<Self> {
        if bytes.len() > MAX_RECORDED_MODEL_BYTES { return Err(ModelRunError::Limit); }
        if ContentDigest::sha256(bytes) != expected { return Err(ModelRunError::Mismatch); }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != b"FSSRMDL1" || d.u32()? != 1 || d.text()? != RECORDED_MODEL_DOMAIN {
            return Err(ModelRunError::Mismatch);
        }
        let graph_digest = d.digest()?;
        let graph = decode_canonical_model_ir(d.bytes()?, graph_digest)?;
        let frame_input = d.text()?.to_owned();
        let scale_to_unit = d.bool()?;
        if graph.inputs().len() > 257 || graph.outputs().len() > 256
            || graph.inputs().iter().chain(graph.outputs()).any(|p| p.dtype() != DType::F32)
        { return Err(ModelRunError::UnsupportedInput); }
        let port = graph.find_input(&frame_input).ok_or(ModelRunError::UnsupportedInput)?;
        let dims = port.shape().dims();
        if dims.len() != 4 || dims[0] != 1 || dims[1] != 1
            || dims[2] == 0 || dims[3] == 0 || dims[2] > 4096 || dims[3] > 4096
            || dims[2].checked_mul(dims[3]).is_none_or(|n| n > 4_194_304)
        { return Err(ModelRunError::UnsupportedInput); }
        let n = usize::try_from(d.u64()?).map_err(|_| ModelRunError::Limit)?;
        if n > 256 || n.checked_add(1) != Some(graph.inputs().len()) || n > d.remaining() / 16 {
            return Err(ModelRunError::Mismatch);
        }
        let mut parameters = BTreeMap::new();
        let mut previous: Option<String> = None;
        for _ in 0..n {
            let name = d.text()?.to_owned();
            if name == frame_input || previous.as_ref().is_some_and(|p| p >= &name) {
                return Err(ModelRunError::Mismatch);
            }
            let port = graph.find_input(&name).ok_or(ModelRunError::UnsupportedInput)?;
            let count = usize::try_from(d.u64()?).map_err(|_| ModelRunError::Limit)?;
            if count != port.shape().num_elements()? || count > d.remaining() / 4 {
                return Err(ModelRunError::Mismatch);
            }
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                let value = f32::from_bits(d.u32()?);
                if !value.is_finite() { return Err(ModelRunError::NonFinite); }
                values.push(value);
            }
            previous = Some(name.clone());
            parameters.insert(name, values);
        }
        d.ensure_finished()?;
        Ok(Self { graph, frame_input, scale_to_unit, parameters, bytes: bytes.to_vec(), digest: expected })
    }

    /// Exact canonical graph and immutable generation.
    #[must_use]
    pub fn graph(&self) -> &ModelIrGraph { &self.graph }
    /// Complete model object identity, including weights and preprocessing.
    #[must_use]
    pub fn digest(&self) -> ContentDigest { self.digest }
    /// Canonical model bytes to retain/export for later execution.
    #[must_use]
    pub fn encoded(&self) -> &[u8] { &self.bytes }
    /// Named image input; all other input ports have explicit frozen parameter values.
    #[must_use]
    pub fn frame_input(&self) -> &str { &self.frame_input }

    pub(super) fn bind(&self, frame: &RecordedFrame, budget: ExecBudget) -> Result<Vec<(String, Tensor)>> {
        if budget.max_bytes == 0 || budget.max_bytes > MAX_RUN_TENSOR_BYTES { return Err(ModelRunError::Limit); }
        let input_bytes = self.graph.inputs().iter().try_fold(0_usize, |sum, port| {
            sum.checked_add(port.shape().size_bytes(DType::F32)?).ok_or(ModelRunError::Limit)
        })?;
        if input_bytes > budget.max_bytes { return Err(ModelRunError::Limit); }
        let port = self.graph.find_input(&self.frame_input).ok_or(ModelRunError::UnsupportedInput)?;
        let dims = port.shape().dims();
        let [width, height] = frame.receipt().dimensions();
        if dims[2] != height as usize || dims[3] != width as usize { return Err(ModelRunError::UnsupportedInput); }
        let program = PreprocessProgram::new(height as usize, width as usize,
            ChannelTransform::LumaOnly, self.scale_to_unit);
        let image = program.execute_bytes(frame.pixels(), height as usize, width as usize, 1, self.graph.generation())?;
        let mut inputs = vec![(self.frame_input.clone(), image)];
        for (name, values) in &self.parameters {
            let port = self.graph.find_input(name).ok_or(ModelRunError::UnsupportedInput)?;
            inputs.push((name.clone(), Tensor::from_values(port.shape().clone(), values, self.graph.generation())?));
        }
        Ok(inputs)
    }
}

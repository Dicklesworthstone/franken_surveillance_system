#![forbid(unsafe_code)]
//! Native JPEG color -> source privacy mask -> resize/letterbox -> frozen F32 Model IR.
//!
//! Reuses the existing native codec, preprocessing and scalar executor. Parameters must
//! be explicitly supplied; none are downloaded, randomized, guessed or substituted. This
//! is synchronous computation, not registry activation, retained publication, a trained
//! detector distribution, calibrated threat assessment or alert/effect authority.

use std::collections::BTreeMap;
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeError};
use fss_codec_mjpeg::color::{DecodedRgb, RgbDecodeLimits, RgbDecodeReceipt, decode_rgb, rgb_decoder_identity};
use fss_core::{CanonicalEncoder, ContentDigest, ContractError};
use fss_model_ir::{GraphValidator, ModelIrGraph, encode_canonical_model_ir};
use fss_tensor::{DType, Tensor, TensorError};
use crate::preprocess::{ImageBytes, ResizeAspect, ResizeFilter, ResizeGeometry, ResizeOptions};
use crate::{ChannelTransform, ExecBudget, ExecError, PreprocessProgram, ScalarExecCx, ScalarExecutor};

/// Maximum canonical graph plus raw F32 parameters for this bounded computation lane.
pub const MAX_RGB_MODEL_BYTES: usize = 16 * 1024 * 1024;
/// Complete output bytes ceiling, never permission to truncate tensors or detections.
pub const MAX_RGB_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// Explicit preprocessing semantics, frozen together with the graph and parameters.
#[derive(Clone, Debug)]
pub struct RgbModelSpec {
    /// Single graph image input; every other input must have an exact parameter binding.
    pub image_input: String,
    /// RGB NCHW target and raw-byte/[0,1] normalization; luma conversion is refused.
    pub preprocess: PreprocessProgram,
    /// Existing native resampling algorithm.
    pub filter: ResizeFilter,
    /// Existing aspect/letterbox policy; exact inverse geometry travels with each output.
    pub aspect: ResizeAspect,
    /// Substitute only this public constant at denied source pixels BEFORE resampling.
    pub masked_rgb: [u8; 3],
}

/// Separate bounded owners for decode, preprocessing and graph execution.
#[derive(Clone, Copy, Debug)]
pub struct RgbRunLimits {
    /// Source-frame/RGB limits for run_jpeg; run_decoded consumes an already validated decode.
    pub decode: RgbDecodeLimits,
    /// Masking plus the existing resize work/buffer bounds, excluding the decoder's buffer.
    pub preprocess: ExecBudget,
    /// Existing scalar executor's cumulative input/intermediate tensor and operation bounds.
    pub execution: ExecBudget,
    /// Full returned tensor-value set plus canonical hashing overhead.
    pub maximum_output_bytes: usize,
}

/// Original owner-supplied source and permission bindings, not authentication or a grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RgbSourceBinding {
    /// Independently expected complete JPEG digest.
    pub encoded_sha256: [u8; 32],
    /// Exact original source exposure, not a new ID invented by decoding.
    pub exposure: [u8; 32],
    /// Physical camera handle, nonzero, retained but not interpreted here.
    pub camera: u64,
    /// Owner capture-clock generation, nonzero.
    pub clock: u64,
    /// Earliest/latest possible capture times; inference never makes them exact.
    pub capture: [u64; 2],
    /// Owner image-domain identity before native decoding and resizing.
    pub image_domain: [u8; 32],
    /// Owner calibration identity, distinct from model tensor generation.
    pub calibration: [u8; 32],
    /// SHA-256 of exactly width*height current 0/1 permission bytes.
    pub permission_mask: [u8; 32],
}

/// No failure returns partial model tensors or mutates a tracker/ledger.
#[derive(Debug)]
pub enum RgbInferenceError {
    /// Invalid image contract, parameter binding, mask, source or generation.
    InvalidInput,
    /// Configured model, intermediate, input or complete-output bound exceeded.
    Limit,
    /// Exact source or permission bytes contradict their supplied identities.
    SourceMismatch,
    /// Nonfinite parameter or model output; never interpreted as an empty detection set.
    NonFinite,
    /// Canonical graph validation/encoding failed.
    Graph(fss_model_ir::ModelIrError),
    /// Complete native source decoding failed or was interrupted.
    Decode(DecodeError),
    /// Existing preprocessing/execution failed or its owner requested cancellation.
    Execution(ExecError),
    /// Tensor construction/materialization failed.
    Tensor(TensorError),
    /// Canonical derivation fingerprint could not be encoded.
    Contract(ContractError),
}
impl std::fmt::Display for RgbInferenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid RGB model, source or mask contract",
            Self::Limit => "RGB inference complete-output or resource bound",
            Self::SourceMismatch => "RGB source or permission digest mismatch",
            Self::NonFinite => "nonfinite RGB model parameter or output",
            Self::Graph(_) => "RGB model graph refused",
            Self::Decode(_) => "RGB JPEG decoding failed",
            Self::Execution(_) => "RGB preprocessing or model execution refused",
            Self::Tensor(_) => "RGB tensor construction failed",
            Self::Contract(_) => "RGB derivation encoding failed",
        })
    }
}
impl std::error::Error for RgbInferenceError {}
macro_rules! convert {
    ($from:ty, $variant:ident) => {
        impl From<$from> for RgbInferenceError {
            fn from(error: $from) -> Self { Self::$variant(error) }
        }
    };
}
convert!(fss_model_ir::ModelIrError, Graph);
convert!(DecodeError, Decode);
convert!(ExecError, Execution);
convert!(TensorError, Tensor);
convert!(ContractError, Contract);
type Result<T> = std::result::Result<T, RgbInferenceError>;

/// Frozen image program, graph and complete owned parameter values. No mutable tensor aliases.
#[derive(Debug)]
pub struct RgbInferenceModel {
    graph: ModelIrGraph,
    spec: RgbModelSpec,
    parameters: BTreeMap<String, Vec<f32>>,
    digest: ContentDigest,
    input_bytes: usize,
    output_bytes: usize,
}
impl RgbInferenceModel {
    /// Validate and freeze an explicitly authored/converted RGB graph and all F32 weights.
    /// There is no implied framework conversion, model quality, license or deployment approval.
    pub fn new(graph: &ModelIrGraph, parameters: BTreeMap<String, Vec<f32>>,
        spec: RgbModelSpec, cx: &ScalarExecCx) -> Result<Self> {
        cx.checkpoint("rgb-model:validate")?;
        let p = &spec.preprocess;
        if spec.image_input.is_empty() || spec.image_input.len() > 128
            || p.channel_transform != ChannelTransform::Rgb || p.target_height == 0 || p.target_width == 0
            || p.target_height > 4096 || p.target_width > 4096
            || p.target_height.checked_mul(p.target_width).is_none_or(|n| n > 4_194_304)
            || graph.nodes().len() > 1024 || graph.inputs().len() > 257 || graph.outputs().len() > 256
            || graph.outputs().is_empty() || parameters.len() + 1 != graph.inputs().len()
            || graph.inputs().iter().chain(graph.outputs()).any(|port| port.dtype() != DType::F32)
            || parameters.contains_key(&spec.image_input) {
            return Err(RgbInferenceError::InvalidInput);
        }
        GraphValidator::validate(graph)?;
        let image = graph.find_input(&spec.image_input).ok_or(RgbInferenceError::InvalidInput)?;
        if image.shape().dims() != [1, 3, p.target_height, p.target_width] {
            return Err(RgbInferenceError::InvalidInput);
        }
        let mut parameter_bytes = 0_usize;
        for port in graph.inputs().iter().filter(|port| port.name() != spec.image_input.as_str()) {
            cx.checkpoint("rgb-model:parameters")?;
            let values = parameters.get(port.name()).ok_or(RgbInferenceError::InvalidInput)?;
            if values.len() != port.shape().num_elements()? { return Err(RgbInferenceError::InvalidInput); }
            parameter_bytes = parameter_bytes.checked_add(values.len().checked_mul(4).ok_or(RgbInferenceError::Limit)?)
                .ok_or(RgbInferenceError::Limit)?;
            if parameter_bytes > MAX_RGB_MODEL_BYTES { return Err(RgbInferenceError::Limit); }
            for chunk in values.chunks(1024) {
                cx.checkpoint("rgb-model:finite")?;
                if chunk.iter().any(|value| !value.is_finite()) { return Err(RgbInferenceError::NonFinite); }
            }
        }
        let graph_bytes = encode_canonical_model_ir(graph)?;
        if graph_bytes.len().checked_add(parameter_bytes).is_none_or(|n| n > MAX_RGB_MODEL_BYTES) {
            return Err(RgbInferenceError::Limit);
        }
        let mut e = CanonicalEncoder::new();
        e.text("fss.rgb-inference-model.reference.v1");
        e.digest(ContentDigest::sha256(&graph_bytes)); e.text(&spec.image_input);
        e.digest(p.resize_digest(spec.filter, spec.aspect)); e.bytes(&spec.masked_rgb);
        // Immutable source fingerprint, not a compiled-binary or hardware qualification claim.
        e.digest(super::inference::executor_profile_digest());
        e.digest(ContentDigest::sha256(include_bytes!("../preprocess.rs")));
        e.digest(ContentDigest::sha256(include_bytes!("rgb_inference.rs")));
        e.bytes(&rgb_decoder_identity());
        e.u64(parameters.len() as u64);
        for (name, values) in &parameters {
            e.text(name); e.u64(values.len() as u64);
            for chunk in values.chunks(1024) {
                cx.checkpoint("rgb-model:fingerprint")?;
                for value in chunk { e.u32(value.to_bits()); }
            }
        }
        let digest = ContentDigest::sha256(&e.finish_checked()?);
        let input_bytes = image.shape().size_bytes(DType::F32)?.checked_add(parameter_bytes).ok_or(RgbInferenceError::Limit)?;
        let mut output_bytes = 64_usize;
        for port in graph.outputs() {
            output_bytes = output_bytes.checked_add(port.shape().size_bytes(DType::F32)?)
                .and_then(|n| n.checked_add(port.name().len() + port.rank() * 8 + 64)).ok_or(RgbInferenceError::Limit)?;
        }
        if output_bytes > MAX_RGB_OUTPUT_BYTES { return Err(RgbInferenceError::Limit); }
        cx.checkpoint("rgb-model:complete")?;
        Ok(Self { graph: graph.clone(), spec, parameters, digest, input_bytes, output_bytes })
    }
    /// Graph, weights, preprocessing and source implementation identity; no activation authority.
    pub fn digest(&self) -> ContentDigest { self.digest }
    /// Exact immutable model/preprocessing choices.
    pub fn spec(&self) -> &RgbModelSpec { &self.spec }

    /// Decode a real JPEG then execute the frozen RGB graph. Both contexts belong to the caller;
    /// the decoder budget should share its owner's cancellation flag. Executor cancellation is
    /// also checked before and after decode. No I/O, threads, retries or publication occur here.
    #[allow(clippy::too_many_arguments)]
    pub fn run_jpeg(&self, bytes: &[u8], interpretation: ComponentInterpretation,
        source: RgbSourceBinding, allowed: &[u8], limits: RgbRunLimits,
        decoder: &mut DecodeBudget<'_>, cx: &ScalarExecCx) -> Result<RgbInference> {
        cx.checkpoint("rgb-inference:decode")?;
        self.admit(source, limits)?;
        if allowed.len() > 4_194_304 { return Err(RgbInferenceError::Limit); }
        let image = decode_rgb(bytes, source.encoded_sha256, interpretation, limits.decode, decoder)?;
        self.run_decoded(&image, source, allowed, limits, cx)
    }

    /// Run on an actual completed native RGB decode. Source privacy projection happens before
    /// interpolation, normalization or model execution, so denied pixel values cannot leak into
    /// neighboring model inputs. Mask and source identities are retained independently.
    pub fn run_decoded(&self, image: &DecodedRgb, source: RgbSourceBinding, allowed: &[u8],
        limits: RgbRunLimits, cx: &ScalarExecCx) -> Result<RgbInference> {
        cx.checkpoint("rgb-inference:mask")?;
        self.admit(source, limits)?;
        if image.receipt().encoded_sha256 != source.encoded_sha256 { return Err(RgbInferenceError::SourceMismatch); }
        let [width, height] = image.dimensions();
        let count = width as usize * height as usize;
        let bytes = image.pixels().len();
        let mask_work = count as u64 * 8 + bytes as u64;
        if allowed.len() != count { return Err(RgbInferenceError::InvalidInput); }
        if bytes > limits.preprocess.max_bytes || mask_work > limits.preprocess.max_macs {
            return Err(RgbInferenceError::Limit);
        }
        for chunk in allowed.chunks(4096) {
            cx.checkpoint("rgb-inference:mask-validation")?;
            if chunk.iter().any(|value| *value > 1) { return Err(RgbInferenceError::InvalidInput); }
        }
        if ContentDigest::sha256(allowed).bytes() != source.permission_mask { return Err(RgbInferenceError::SourceMismatch); }
        let mut masked = Vec::new(); masked.try_reserve_exact(bytes).map_err(|_| RgbInferenceError::Limit)?;
        for (i, permission) in allowed.iter().enumerate() {
            if i % 1024 == 0 { cx.checkpoint("rgb-inference:mask-copy")?; }
            if *permission == 0 { masked.extend_from_slice(&self.spec.masked_rgb); }
            else { masked.extend_from_slice(&image.pixels()[i * 3..i * 3 + 3]); }
        }
        let options = ResizeOptions { filter: self.spec.filter, aspect: self.spec.aspect,
            budget: ExecBudget::new(limits.preprocess.max_macs - mask_work, limits.preprocess.max_bytes - bytes) };
        let resized = self.spec.preprocess.execute_resized_bytes(ImageBytes {
            bytes: &masked, width: width as usize, height: height as usize, channels: 3,
            generation: self.graph.generation(),
        }, options, cx)?;
        let geometry = resized.geometry;
        let input_digest = resized.output_digest;
        let masked_digest = resized.input_digest;
        let mut inputs = vec![(self.spec.image_input.clone(), resized.tensor)];
        for (name, values) in &self.parameters {
            cx.checkpoint("rgb-inference:bind")?;
            let port = self.graph.find_input(name).ok_or(RgbInferenceError::InvalidInput)?;
            inputs.push((name.clone(), Tensor::from_values(port.shape().clone(), values, self.graph.generation())?));
        }
        let executed = ScalarExecutor::run(&self.graph, &inputs, limits.execution, cx)?;
        let mut outputs = BTreeMap::new();
        let mut encoded = CanonicalEncoder::new(); encoded.text("fss.rgb-tensor-result.reference.v1");
        encoded.u64(executed.outputs().len() as u64);
        for (name, tensor) in executed.outputs() {
            cx.checkpoint("rgb-inference:outputs")?;
            let values = tensor.to_vec::<f32>()?;
            encoded.text(name); encoded.u64(tensor.shape().rank() as u64);
            for &n in tensor.shape().dims() { encoded.u64(n as u64); }
            for chunk in values.chunks(1024) {
                cx.checkpoint("rgb-inference:output-finite")?;
                for value in chunk {
                    if !value.is_finite() { return Err(RgbInferenceError::NonFinite); }
                    encoded.u32(value.to_bits());
                }
            }
            outputs.insert(name.clone(), RgbTensorOutput { shape: tensor.shape().dims().to_vec(), values });
        }
        let output_bytes = encoded.finish_checked()?;
        if output_bytes.len() > limits.maximum_output_bytes { return Err(RgbInferenceError::Limit); }
        let output_digest = ContentDigest::sha256(&output_bytes);
        let mut e = CanonicalEncoder::new(); e.text("fss.rgb-inference.reference.v1"); e.digest(self.digest);
        encode_source(&mut e, source); e.bytes(&image.receipt().decoder); e.bytes(&image.receipt().rgb_sha256);
        e.digest(masked_digest); e.digest(input_digest); e.digest(output_digest);
        let identity = ContentDigest::sha256(&e.finish_checked()?);
        cx.checkpoint("rgb-inference:complete")?;
        Ok(RgbInference { identity, model: self.digest, source, decode: image.receipt(), geometry,
            input_digest, masked_digest, output_digest, outputs,
            preprocess_work: mask_work + resized.work_units, executed_macs: executed.executed_macs(),
            allocated_tensor_bytes: executed.allocated_bytes() })
    }

    fn admit(&self, source: RgbSourceBinding, limits: RgbRunLimits) -> Result<()> {
        if source.camera == 0 || source.clock == 0 || source.capture[0] > source.capture[1]
            || [source.encoded_sha256, source.exposure, source.image_domain, source.calibration,
                source.permission_mask].contains(&[0; 32]) {
            return Err(RgbInferenceError::InvalidInput);
        }
        if limits.maximum_output_bytes == 0 || limits.maximum_output_bytes > MAX_RGB_OUTPUT_BYTES
            || self.output_bytes > limits.maximum_output_bytes || self.input_bytes > limits.execution.max_bytes
            || limits.preprocess.max_bytes > 256 * 1024 * 1024 || limits.execution.max_bytes > 256 * 1024 * 1024 {
            return Err(RgbInferenceError::Limit);
        }
        Ok(())
    }
}
fn encode_source(e: &mut CanonicalEncoder, source: RgbSourceBinding) {
    for hash in [source.encoded_sha256, source.exposure, source.image_domain, source.calibration, source.permission_mask] {
        e.bytes(&hash);
    }
    for n in [source.camera, source.clock, source.capture[0], source.capture[1]] { e.u64(n); }
}

/// Immutable F32 output with its exact shape, without mutable Tensor storage aliases.
#[derive(Debug)]
pub struct RgbTensorOutput { shape: Vec<usize>, values: Vec<f32> }
impl RgbTensorOutput {
    /// Exact Model IR output dimensions.
    pub fn shape(&self) -> &[usize] { &self.shape }
    /// Complete finite model values in contiguous row-major order; no class is inferred.
    pub fn values(&self) -> &[f32] { &self.values }
}
/// Complete numerical inference and the source/permission/transform needed to interpret it.
#[derive(Debug)]
pub struct RgbInference {
    identity: ContentDigest, model: ContentDigest, source: RgbSourceBinding, decode: RgbDecodeReceipt,
    geometry: ResizeGeometry, input_digest: ContentDigest, masked_digest: ContentDigest,
    output_digest: ContentDigest, outputs: BTreeMap<String, RgbTensorOutput>,
    preprocess_work: u64, executed_macs: u64, allocated_tensor_bytes: usize,
}
impl RgbInference {
    /// Whole source/model/input/output derivation, not a canonical evidence publication.
    pub fn identity(&self) -> ContentDigest { self.identity }
    /// Exact graph, parameter and preprocessing program used.
    pub fn model_digest(&self) -> ContentDigest { self.model }
    /// Original camera/clock/capture/privacy binding, unchanged by inference.
    pub fn source(&self) -> RgbSourceBinding { self.source }
    /// Actual complete native color decode receipt.
    pub fn decode_receipt(&self) -> RgbDecodeReceipt { self.decode }
    /// Exact geometry for source_box() reversal of model-space boxes and padding rejection.
    pub fn geometry(&self) -> ResizeGeometry { self.geometry }
    /// Privacy-projected HWC input identity; not the unrestricted decoded RGB hash.
    pub fn masked_digest(&self) -> ContentDigest { self.masked_digest }
    /// Exact normalized NCHW tensor identity consumed by the executor.
    pub fn input_digest(&self) -> ContentDigest { self.input_digest }
    /// Shape/name/value fingerprint of the complete finite result tensors.
    pub fn output_digest(&self) -> ContentDigest { self.output_digest }
    /// All declared outputs. A tensor is not automatically a detection or a threat score.
    pub fn outputs(&self) -> &BTreeMap<String, RgbTensorOutput> { &self.outputs }
    /// Logical mask and resizing work, separately bounded from neural operations.
    pub fn preprocess_work(&self) -> u64 { self.preprocess_work }
    /// Existing executor's charged numerical operations.
    pub fn executed_macs(&self) -> u64 { self.executed_macs }
    /// Existing executor's cumulative tensor-buffer allocation accounting.
    pub fn allocated_tensor_bytes(&self) -> usize { self.allocated_tensor_bytes }
}

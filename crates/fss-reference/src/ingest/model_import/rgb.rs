#![forbid(unsafe_code)]
//! Source-preserving Safetensors import for the native RGB inference lane.
//!
//! Reuses the existing bounded container parser and exact F16/BF16 expansion. The
//! graph must already be converted to canonical FSS Model IR; arbitrary framework
//! code, implicit architecture discovery, downloads and model activation are absent.

use std::collections::{BTreeMap, BTreeSet};
use fss_core::{CanonicalEncoder, ContentDigest};
use fss_model_ir::decode_canonical_model_ir;
use fss_tensor::DType;
use crate::{ReplayCx, ScalarExecCx};
use crate::ingest::rgb_inference::{RgbInferenceError, RgbInferenceModel, RgbModelSpec};
use super::{ImportBudget, ImportError, ImportLimits, WeightFloatPolicy, checkpoint, safetensors};

/// Exact offline sources and preprocessing; mappings run graph port -> source tensor name.
#[derive(Debug)]
pub struct RgbModelImportRequest<'a> {
    /// Complete canonical FSS graph, not ONNX, Python or a guessed model architecture.
    pub graph: &'a [u8],
    /// Independently expected graph digest.
    pub graph_digest: ContentDigest,
    /// Complete original Safetensors file, including metadata.
    pub weights: &'a [u8],
    /// Independently expected weight-file digest.
    pub weights_digest: ContentDigest,
    /// Exact RGB preprocessing and named image input, frozen into model identity.
    pub spec: RgbModelSpec,
    /// Explicit finite F32-only or lossless F16/BF16 expansion policy.
    pub float_policy: WeightFloatPolicy,
    /// Empty means exact name equality. Otherwise every parameter port must appear.
    pub bindings: BTreeMap<String, String>,
}

/// Failure publishes no model, no inference, and no incomplete provenance record.
#[derive(Debug)]
pub enum RgbImportError {
    /// The existing source, shape, binding, numeric or resource contract refused import.
    Import(ImportError),
    /// The RGB model/preprocessing contract or execution owner refused the converted model.
    Model(Box<RgbInferenceError>),
}
impl From<ImportError> for RgbImportError {
    fn from(error: ImportError) -> Self { Self::Import(error) }
}
impl From<RgbInferenceError> for RgbImportError {
    fn from(error: RgbInferenceError) -> Self { Self::Model(Box::new(error)) }
}
impl std::fmt::Display for RgbImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Import(_) => "RGB source-weight import refused",
            Self::Model(_) => "RGB model contract refused imported weights",
        })
    }
}
impl std::error::Error for RgbImportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self { Self::Import(e) => Some(e), Self::Model(e) => Some(e.as_ref()) }
    }
}

/// Completed model with exact original sources still borrowed from their owner.
/// No original metadata, unreferenced parameter or malformed suffix is silently dropped.
/// This is an in-memory provenance record, not durable publication or model qualification.
#[derive(Debug)]
pub struct ImportedRgbModel<'a> {
    model: RgbInferenceModel,
    graph: &'a [u8],
    weights: &'a [u8],
    graph_digest: ContentDigest,
    weights_digest: ContentDigest,
    identity: ContentDigest,
    bindings: BTreeMap<String, String>,
    float_policy: WeightFloatPolicy,
    expanded_bytes: usize,
}
impl<'a> ImportedRgbModel<'a> {
    /// Convert all exact parameters and freeze their RGB graph/preprocessing contract.
    ///
    /// Both contexts are caller-owned. Import work is reserved with the existing
    /// ImportBudget; the scalar context owns model construction and later inference.
    /// `maximum_bundle_bytes` bounds original sources plus expanded parameter bytes;
    /// this function borrows those sources rather than serializing a second model format.
    pub fn build(request: &RgbModelImportRequest<'a>, limits: ImportLimits,
        budget: &mut ImportBudget, cx: &ReplayCx, scalar: &ScalarExecCx)
        -> Result<Self, RgbImportError> {
        checkpoint(cx)?;
        limits.validate()?;
        scalar.checkpoint("rgb-import:begin").map_err(RgbInferenceError::from)?;
        let input = &request.spec.image_input;
        if request.graph.len() > limits.maximum_source_bytes || request.weights.len() > limits.maximum_source_bytes
            || input.is_empty() || input.len() > 128 || request.bindings.len() > limits.maximum_tensors
            || request.bindings.iter().any(|(a,b)| a.is_empty() || b.is_empty()
                || a.len() > safetensors::MAX_NAME || b.len() > safetensors::MAX_NAME) {
            return Err(ImportError::Limit.into());
        }
        budget.charge(request.graph.len() + request.weights.len(), cx)?;
        if ContentDigest::sha256(request.graph) != request.graph_digest
            || ContentDigest::sha256(request.weights) != request.weights_digest {
            return Err(ImportError::DigestMismatch.into());
        }
        let graph = decode_canonical_model_ir(request.graph, request.graph_digest)
            .map_err(|_| ImportError::InvalidGraph)?;
        let image = graph.find_input(input).ok_or(ImportError::BindingMismatch)?;
        let p = &request.spec.preprocess;
        if image.dtype() != DType::F32 || image.shape().dims() != [1, 3, p.target_height, p.target_width] {
            return Err(ImportError::BindingMismatch.into());
        }
        budget.charge(request.weights.len(), cx)?;
        let weights = safetensors::Weights::parse(request.weights, &limits)?;
        let params: Vec<_> = graph.inputs().iter().filter(|port| port.name() != input.as_str()).collect();
        if params.len() > limits.maximum_tensors { return Err(ImportError::Limit.into()); }
        let bindings = if request.bindings.is_empty() {
            params.iter().map(|port| (port.name().to_owned(), port.name().to_owned())).collect::<BTreeMap<_,_>>()
        } else { request.bindings.clone() };
        if bindings.len() != params.len() || bindings.contains_key(input) { return Err(ImportError::BindingMismatch.into()); }
        let mut referenced = BTreeSet::new();
        let mut expanded_bytes = 0_usize;
        for port in params {
            checkpoint(cx)?;
            let name = bindings.get(port.name()).ok_or(ImportError::BindingMismatch)?;
            let entry = weights.entries.get(name).ok_or(ImportError::BindingMismatch)?;
            if port.dtype() != DType::F32 || port.shape().dims() != entry.shape.as_slice() {
                return Err(ImportError::BindingMismatch.into());
            }
            if entry.dtype != safetensors::FloatType::F32 && request.float_policy == WeightFloatPolicy::F32Only {
                return Err(ImportError::UnsupportedDType.into());
            }
            expanded_bytes = expanded_bytes.checked_add(safetensors::element_count(&entry.shape)?
                .checked_mul(4).ok_or(ImportError::Limit)?).ok_or(ImportError::Limit)?;
            if expanded_bytes > limits.maximum_expanded_bytes { return Err(ImportError::Limit.into()); }
            referenced.insert(name);
        }
        if referenced.len() != weights.entries.len() { return Err(ImportError::BindingMismatch.into()); }
        let total = request.graph.len().checked_add(request.weights.len())
            .and_then(|n| n.checked_add(expanded_bytes)).ok_or(ImportError::Limit)?;
        if total > limits.maximum_bundle_bytes { return Err(ImportError::Limit.into()); }
        budget.charge(expanded_bytes.checked_mul(4).ok_or(ImportError::Limit)?, cx)?;
        let mut parameters = BTreeMap::new();
        for (port, name) in &bindings {
            let entry = weights.entries.get(name).ok_or(ImportError::BindingMismatch)?;
            let source = weights.data.get(entry.start..entry.end).ok_or(ImportError::MalformedWeights)?;
            let mut values = Vec::new();
            values.try_reserve_exact(safetensors::element_count(&entry.shape)?).map_err(|_| ImportError::Limit)?;
            for (i, chunk) in source.chunks_exact(entry.width()).enumerate() {
                if i % 1024 == 0 {
                    checkpoint(cx)?;
                    scalar.checkpoint("rgb-import:convert").map_err(RgbInferenceError::from)?;
                }
                values.push(safetensors::value(entry.dtype, chunk, request.float_policy)?);
            }
            parameters.insert(port.clone(), values);
        }
        budget.charge(request.graph.len() + expanded_bytes, cx)?;
        let model = RgbInferenceModel::new(&graph, parameters, request.spec.clone(), scalar)?;
        let recipe_work = 1024 + bindings.iter().map(|(port, name)| port.len() + name.len() + 16).sum::<usize>();
        budget.charge(recipe_work + include_bytes!("rgb.rs").len() + include_bytes!("safetensors.rs").len(), cx)?;
        let mut e = CanonicalEncoder::new();
        e.text("fss.rgb-weight-import.reference.v1");
        e.digest(ContentDigest::sha256(include_bytes!("rgb.rs")));
        e.digest(ContentDigest::sha256(include_bytes!("safetensors.rs")));
        e.digest(request.graph_digest); e.digest(request.weights_digest); e.digest(model.digest());
        e.u8(match request.float_policy { WeightFloatPolicy::F32Only => 0, WeightFloatPolicy::ExpandFloat16 => 1 });
        e.u64(bindings.len() as u64);
        for (port, name) in &bindings { e.text(port); e.text(name); }
        let bytes = e.finish_checked().map_err(ImportError::from)?;
        let identity = ContentDigest::sha256(&bytes);
        checkpoint(cx)?;
        scalar.checkpoint("rgb-import:complete").map_err(RgbInferenceError::from)?;
        Ok(Self { model, graph: request.graph, weights: request.weights, graph_digest: request.graph_digest,
            weights_digest: request.weights_digest, identity, bindings,
            float_policy: request.float_policy, expanded_bytes })
    }
    /// Frozen, immediately executable RGB model; original source provenance remains here.
    pub fn model(&self) -> &RgbInferenceModel { &self.model }
    /// Complete original canonical graph bytes, borrowed rather than rewritten.
    pub fn graph_source(&self) -> &'a [u8] { self.graph }
    /// Complete original Safetensors file, including all metadata/header bytes.
    pub fn weights_source(&self) -> &'a [u8] { self.weights }
    /// Exact supplied graph identity.
    pub fn graph_digest(&self) -> ContentDigest { self.graph_digest }
    /// Exact supplied weight-file identity, distinct from expanded numerical parameters.
    pub fn weights_digest(&self) -> ContentDigest { self.weights_digest }
    /// Source/recipe/converted-model/implementation identity, not a durable ledger anchor.
    pub fn identity(&self) -> ContentDigest { self.identity }
    /// Complete graph-port to source-name mapping, including explicit shared-source aliases.
    pub fn bindings(&self) -> &BTreeMap<String, String> { &self.bindings }
    /// Exact original float-conversion permission.
    pub fn float_policy(&self) -> WeightFloatPolicy { self.float_policy }
    /// Actual expanded F32 parameter bytes, including aliases, not peak process memory.
    pub fn expanded_bytes(&self) -> usize { self.expanded_bytes }
}

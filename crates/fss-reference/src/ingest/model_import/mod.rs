#![forbid(unsafe_code)]
//! Offline, source-preserving Safetensors conversion into the existing recorded model format.
//!
//! Inputs are data, not model code. The caller supplies the already-converted canonical graph,
//! exact source digests, name mapping, and preprocessing. This does not discover architectures,
//! admit a model to production, certify its license/quality, activate it, or execute inference.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, ContractError};
use fss_model_ir::decode_canonical_model_ir;
use fss_tensor::DType;
use crate::ReplayCx;
use super::inference::{MAX_RECORDED_MODEL_BYTES, ModelRunError, RecordedModel};

mod safetensors;

/// Source-weight/graph byte ceiling; deliberately narrower than the upstream general format.
pub const MAX_IMPORT_SOURCE_BYTES: usize = 16 * 1024 * 1024;
/// Header ceiling checked before any JSON allocation.
pub const MAX_IMPORT_HEADER_BYTES: usize = 256 * 1024;
/// Self-contained graph + original weights + converted model + recipe ceiling.
pub const MAX_IMPORT_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
const MAX_TENSORS: usize = 256;
const DOMAIN: &str = "fss.recorded_model_import.v1";

/// Explicit source numeric policy. Expansion is exact for all finite half-precision values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WeightFloatPolicy {
    /// Admit F32 only; preserve each finite source bit pattern, including signed zero.
    F32Only,
    /// Also admit F16 and BF16 and exactly expand them to the existing F32 execution input.
    ExpandFloat16,
}

/// Independent caller ceilings. None silently drops parameters or changes their precision.
#[derive(Clone, Copy, Debug)]
pub struct ImportLimits {
    /// Maximum bytes of each graph or original Safetensors file.
    pub maximum_source_bytes: usize,
    /// Maximum Safetensors JSON header bytes.
    pub maximum_header_bytes: usize,
    /// Maximum source tensors and mapped graph parameter ports.
    pub maximum_tensors: usize,
    /// Maximum sum of expanded parameter bytes, including explicitly shared-source bindings.
    pub maximum_expanded_bytes: usize,
    /// Maximum complete import-bundle bytes.
    pub maximum_bundle_bytes: usize,
}
impl Default for ImportLimits {
    fn default() -> Self {
        Self { maximum_source_bytes: MAX_IMPORT_SOURCE_BYTES, maximum_header_bytes: MAX_IMPORT_HEADER_BYTES,
            maximum_tensors: MAX_TENSORS, maximum_expanded_bytes: MAX_RECORDED_MODEL_BYTES,
            maximum_bundle_bytes: MAX_IMPORT_BUNDLE_BYTES }
    }
}
impl ImportLimits {
    fn validate(self) -> Result<(), ImportError> {
        if self.maximum_source_bytes == 0 || self.maximum_source_bytes > MAX_IMPORT_SOURCE_BYTES
            || self.maximum_header_bytes == 0 || self.maximum_header_bytes > MAX_IMPORT_HEADER_BYTES
            || self.maximum_tensors > MAX_TENSORS || self.maximum_expanded_bytes > MAX_RECORDED_MODEL_BYTES
            || self.maximum_bundle_bytes == 0 || self.maximum_bundle_bytes > MAX_IMPORT_BUNDLE_BYTES
        { return Err(ImportError::Limit); }
        Ok(())
    }
}

/// Cumulative admission work for source bytes, parameter conversion and output encoding.
/// These deterministic reservations are not CPU time or total process-memory accounting.
#[derive(Debug)]
pub struct ImportBudget { remaining: u64, used: u64 }
impl ImportBudget {
    /// Create a bounded allowance, shared across import or independent verification calls.
    #[must_use]
    pub fn new(units: u64) -> Self { Self { remaining: units, used: 0 } }
    /// Work charged, including a refused attempt; charges are never refunded.
    #[must_use]
    pub fn used(&self) -> u64 { self.used }
    /// Remaining allowance.
    #[must_use]
    pub fn remaining(&self) -> u64 { self.remaining }
    fn charge(&mut self, units: usize, cx: &ReplayCx) -> Result<(), ImportError> {
        checkpoint(cx)?;
        let units = u64::try_from(units).map_err(|_| ImportError::Limit)?;
        if units > self.remaining { return Err(ImportError::BudgetExceeded); }
        self.remaining -= units; self.used += units; Ok(())
    }
}

/// Complete import recipe. An empty mapping means exact source-name = graph-port matching.
/// A nonempty mapping must cover every non-image graph input; no unreferenced source tensor
/// is silently discarded. Several explicitly named ports may share the same source tensor.
#[derive(Debug)]
pub struct ModelImportRequest<'a> {
    /// Exact canonical FSS Model IR bytes, not ONNX, Python, or a vendor config.
    pub graph: &'a [u8],
    /// Independently expected graph content identity.
    pub graph_digest: ContentDigest,
    /// Complete original Safetensors bytes, including all metadata and data.
    pub weights: &'a [u8],
    /// Independently expected original-file identity.
    pub weights_digest: ContentDigest,
    /// The single full-resolution `[1,1,H,W]` luma input in the graph.
    pub frame_input: &'a str,
    /// Explicit existing recorded-model scaling: bytes to [0,1], or raw byte-valued F32.
    pub scale_to_unit: bool,
    /// Which source float representations are admitted.
    pub float_policy: WeightFloatPolicy,
    /// Graph parameter port -> source tensor name, not the inverse mapping.
    pub bindings: BTreeMap<String, String>,
}

/// Typed, non-disclosing import refusal. Nothing is published and no incomplete model escapes.
#[derive(Debug)]
pub enum ImportError {
    /// A hard or caller byte/count/shape bound was exceeded.
    Limit,
    /// Source or reconstructed bundle digest differs from the expected identity.
    DigestMismatch,
    /// The original weight container is malformed or has holes/overlaps/unindexed bytes.
    MalformedWeights,
    /// A duplicate JSON key, including an escaped alias, is ambiguous.
    DuplicateKey,
    /// The source dtype is not admitted by the explicit conversion policy.
    UnsupportedDType,
    /// A source parameter contains NaN or infinity.
    NonFinite,
    /// Source names, shapes or parameter bindings do not exactly match the supplied graph.
    BindingMismatch,
    /// The supplied graph is not a valid canonical FSS graph.
    InvalidGraph,
    /// Owner cancellation was observed before returning a complete model.
    Cancelled,
    /// The shared deterministic import allowance is exhausted.
    BudgetExceeded,
    /// This bundle belongs to another importer implementation or has an invalid recipe.
    InvalidBundle,
    /// The existing recorded-model contract rejected the converted inputs.
    Model(Box<ModelRunError>),
    /// A canonical encoding failed.
    Contract(ContractError),
}
impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Limit => "model import bound exceeded", Self::DigestMismatch => "model import digest mismatch",
            Self::MalformedWeights => "malformed or noncontiguous Safetensors input", Self::DuplicateKey => "duplicate Safetensors key",
            Self::UnsupportedDType => "source dtype not admitted by import policy", Self::NonFinite => "nonfinite model parameter",
            Self::BindingMismatch => "model parameter names or shapes do not match", Self::InvalidGraph => "invalid canonical model graph",
            Self::Cancelled => "model import cancelled", Self::BudgetExceeded => "model import work budget exhausted",
            Self::InvalidBundle => "invalid or incompatible model import bundle", Self::Model(_) => "recorded model contract refused import",
            Self::Contract(_) => "invalid model import canonical encoding",
        })
    }
}
impl Error for ImportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self { Self::Model(e) => Some(e), Self::Contract(e) => Some(e), _ => None }
    }
}
impl From<ContractError> for ImportError { fn from(e: ContractError) -> Self { Self::Contract(e) } }
impl From<ModelRunError> for ImportError { fn from(e: ModelRunError) -> Self { Self::Model(Box::new(e)) } }
fn checkpoint(cx: &ReplayCx) -> Result<(), ImportError> {
    cx.checkpoint("model_import:work").map_err(|_| ImportError::Cancelled)
}

/// Source-bound importer identity, separate from the unchanged numeric executor profile.
#[must_use]
pub fn importer_identity() -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text("fss.recorded_model_importer.v1");
    e.digest(ContentDigest::sha256(include_bytes!("mod.rs")));
    e.digest(ContentDigest::sha256(include_bytes!("safetensors.rs")));
    ContentDigest::sha256(&e.finish())
}

// An empty-payload pass measures the exact framing/mapping overhead before allocating
// the source-bearing bundle. A narrow output ceiling therefore bounds the allocation too.
fn encode_bundle(request: &ModelImportRequest<'_>, bindings: &BTreeMap<String, String>, model: &[u8],
    profile: ContentDigest, include_payloads: bool) -> Result<Vec<u8>, ImportError> {
    let mut e = CanonicalEncoder::new();
    e.bytes(b"FSSIMPT1"); e.u32(1); e.text(DOMAIN); e.digest(profile);
    e.bytes(if include_payloads { request.graph } else { &[] });
    e.bytes(if include_payloads { request.weights } else { &[] });
    e.text(request.frame_input); e.bool(request.scale_to_unit);
    e.u8(match request.float_policy { WeightFloatPolicy::F32Only => 0, WeightFloatPolicy::ExpandFloat16 => 1 });
    e.u64(bindings.len() as u64);
    for (port, name) in bindings { e.text(port); e.text(name); }
    e.bytes(if include_payloads { model } else { &[] });
    Ok(e.finish_checked()?)
}

/// A converted model plus its complete original inputs and exact reproducible import recipe.
/// The bundle is audit evidence, not a license, quality, authenticity or activation certificate.
#[derive(Debug)]
pub struct ImportedModel {
    model: RecordedModel,
    bytes: Vec<u8>,
    digest: ContentDigest,
    graph_digest: ContentDigest,
    weights_digest: ContentDigest,
    parameter_count: usize,
    expanded_bytes: usize,
}
impl ImportedModel {
    /// Convert all graph parameters after exact whole-container validation. This is memory-only:
    /// filesystem custody/export is a separate explicitly authorized caller operation.
    pub fn build(request: &ModelImportRequest<'_>, limits: ImportLimits, budget: &mut ImportBudget, cx: &ReplayCx) -> Result<Self, ImportError> {
        checkpoint(cx)?; limits.validate()?;
        if request.graph.len() > limits.maximum_source_bytes || request.weights.len() > limits.maximum_source_bytes
            || request.frame_input.is_empty() || request.frame_input.len() > safetensors::MAX_NAME
            || request.bindings.len() > limits.maximum_tensors
            || request.bindings.iter().any(|(a,b)| a.is_empty() || b.is_empty() || a.len() > safetensors::MAX_NAME || b.len() > safetensors::MAX_NAME)
        { return Err(ImportError::Limit); }
        budget.charge(request.graph.len() + request.weights.len(), cx)?;
        if ContentDigest::sha256(request.graph) != request.graph_digest
            || ContentDigest::sha256(request.weights) != request.weights_digest
        { return Err(ImportError::DigestMismatch); }
        let graph = decode_canonical_model_ir(request.graph, request.graph_digest).map_err(|_| ImportError::InvalidGraph)?;
        budget.charge(request.weights.len(), cx)?;
        let weights = safetensors::Weights::parse(request.weights, &limits)?;
        let image = graph.find_input(request.frame_input).ok_or(ImportError::BindingMismatch)?;
        if image.dtype() != DType::F32 { return Err(ImportError::BindingMismatch); }
        let params: Vec<_> = graph.inputs().iter().filter(|p| p.name() != request.frame_input).collect();
        if params.len() > limits.maximum_tensors { return Err(ImportError::Limit); }
        let bindings = if request.bindings.is_empty() {
            params.iter().map(|p| (p.name().to_owned(), p.name().to_owned())).collect::<BTreeMap<_,_>>()
        } else { request.bindings.clone() };
        if bindings.len() != params.len() || bindings.contains_key(request.frame_input) { return Err(ImportError::BindingMismatch); }
        let mut referenced = BTreeSet::new(); let mut expanded_bytes = 0_usize;
        for port in &params {
            checkpoint(cx)?;
            let name = bindings.get(port.name()).ok_or(ImportError::BindingMismatch)?;
            let entry = weights.entries.get(name).ok_or(ImportError::BindingMismatch)?;
            if port.dtype() != DType::F32 || port.shape().dims() != entry.shape.as_slice() { return Err(ImportError::BindingMismatch); }
            if entry.dtype != safetensors::FloatType::F32 && request.float_policy == WeightFloatPolicy::F32Only {
                return Err(ImportError::UnsupportedDType);
            }
            referenced.insert(name);
            expanded_bytes = expanded_bytes.checked_add(safetensors::element_count(&entry.shape)?.checked_mul(4).ok_or(ImportError::Limit)?).ok_or(ImportError::Limit)?;
            if expanded_bytes > limits.maximum_expanded_bytes { return Err(ImportError::Limit); }
        }
        if referenced.len() != weights.entries.len() { return Err(ImportError::BindingMismatch); }
        // Four work units per expanded byte cover the fixed finite-value conversion schedule.
        // Reserve encoding work separately; a caller cannot multiply work by adding aliases.
        budget.charge(expanded_bytes.checked_mul(4).ok_or(ImportError::Limit)?, cx)?;
        let mut parameters = BTreeMap::new();
        for (port, name) in &bindings {
            checkpoint(cx)?;
            let entry = weights.entries.get(name).ok_or(ImportError::BindingMismatch)?;
            let source = weights.data.get(entry.start..entry.end).ok_or(ImportError::MalformedWeights)?;
            let mut values = Vec::new();
            values.try_reserve_exact(safetensors::element_count(&entry.shape)?).map_err(|_| ImportError::Limit)?;
            for (i, chunk) in source.chunks_exact(entry.width()).enumerate() {
                if i % 1024 == 0 { checkpoint(cx)?; }
                values.push(safetensors::value(entry.dtype, chunk, request.float_policy)?);
            }
            parameters.insert(port.clone(), values);
        }
        budget.charge(request.graph.len() + expanded_bytes, cx)?;
        let model = RecordedModel::publish(&graph, request.frame_input, request.scale_to_unit, parameters)?;
        checkpoint(cx)?;
        let profile = importer_identity();
        let overhead = encode_bundle(request, &bindings, model.encoded(), profile, false)?.len();
        let total = overhead.checked_add(request.graph.len()).and_then(|n| n.checked_add(request.weights.len()))
            .and_then(|n| n.checked_add(model.encoded().len())).ok_or(ImportError::Limit)?;
        if total > limits.maximum_bundle_bytes { return Err(ImportError::Limit); }
        budget.charge(total, cx)?;
        let bytes = encode_bundle(request, &bindings, model.encoded(), profile, true)?;
        if bytes.len() != total { return Err(ImportError::InvalidBundle); }
        let digest = ContentDigest::sha256(&bytes);
        checkpoint(cx)?;
        Ok(Self { model, bytes, digest, graph_digest: request.graph_digest, weights_digest: request.weights_digest,
            parameter_count: params.len(), expanded_bytes })
    }

    /// Independently reproduce a digest-pinned bundle from its original graph and weights.
    /// Do not trust an embedded converted model merely because its envelope hashes correctly.
    pub fn verify(bytes: &[u8], expected: ContentDigest, limits: ImportLimits, budget: &mut ImportBudget, cx: &ReplayCx) -> Result<Self, ImportError> {
        checkpoint(cx)?; limits.validate()?;
        if bytes.len() > limits.maximum_bundle_bytes { return Err(ImportError::Limit); }
        budget.charge(bytes.len(), cx)?;
        if ContentDigest::sha256(bytes) != expected { return Err(ImportError::DigestMismatch); }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != b"FSSIMPT1" || d.u32()? != 1 || d.text()? != DOMAIN || d.digest()? != importer_identity() {
            return Err(ImportError::InvalidBundle);
        }
        let graph = d.bytes()?; let weights = d.bytes()?; let frame_input = d.text()?; let scale_to_unit = d.bool()?;
        let float_policy = match d.u8()? { 0 => WeightFloatPolicy::F32Only, 1 => WeightFloatPolicy::ExpandFloat16,
            _ => return Err(ImportError::InvalidBundle) };
        let n = usize::try_from(d.u64()?).map_err(|_| ImportError::Limit)?;
        if n > limits.maximum_tensors { return Err(ImportError::Limit); }
        let mut bindings = BTreeMap::new(); let mut previous: Option<&str> = None;
        for _ in 0..n {
            let port = d.text()?; let name = d.text()?;
            if port.len() > safetensors::MAX_NAME || name.len() > safetensors::MAX_NAME { return Err(ImportError::Limit); }
            if previous.is_some_and(|p| p >= port) { return Err(ImportError::InvalidBundle); }
            bindings.insert(port.to_owned(), name.to_owned()); previous = Some(port);
        }
        let embedded = d.bytes()?; d.ensure_finished()?;
        if embedded.len() > MAX_RECORDED_MODEL_BYTES || graph.len() > limits.maximum_source_bytes || weights.len() > limits.maximum_source_bytes {
            return Err(ImportError::Limit);
        }
        let request = ModelImportRequest { graph, graph_digest: ContentDigest::sha256(graph), weights,
            weights_digest: ContentDigest::sha256(weights), frame_input, scale_to_unit, float_policy, bindings };
        let restored = Self::build(&request, limits, budget, cx)?;
        if restored.encoded() != bytes { return Err(ImportError::InvalidBundle); }
        Ok(restored)
    }
    /// Existing recorded-model format, immediately usable by the retained inference pipeline.
    #[must_use]
    pub fn model(&self) -> &RecordedModel { &self.model }
    /// Complete self-contained audit/reproduction bundle; contains the original source files.
    #[must_use]
    pub fn encoded(&self) -> &[u8] { &self.bytes }
    /// Exact import bundle digest, distinct from the converted model digest.
    #[must_use]
    pub fn digest(&self) -> ContentDigest { self.digest }
    /// Exact original canonical graph digest.
    #[must_use]
    pub fn graph_digest(&self) -> ContentDigest { self.graph_digest }
    /// Exact original Safetensors file digest, including metadata and header layout.
    #[must_use]
    pub fn weights_digest(&self) -> ContentDigest { self.weights_digest }
    /// Number of frozen graph parameter ports, not number of independent observations.
    #[must_use]
    pub fn parameter_count(&self) -> usize { self.parameter_count }
    /// Expanded F32 parameter byte count, not total peak process memory.
    #[must_use]
    pub fn expanded_bytes(&self) -> usize { self.expanded_bytes }
}

#[cfg(test)]
mod tests;


/// Exact Safetensors bindings for native RGB image inference, without changing the luma format.
pub mod rgb;

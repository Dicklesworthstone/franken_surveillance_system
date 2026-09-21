#![forbid(unsafe_code)]
//! Source-closed RGB replay: original JPEG, permissions, graph and Safetensors.
//!
//! A restored envelope is not a verified inference. Only actual native decode,
//! import, execution and head projection can return a `ReplayedRgbEvidence`.
//! Source declarations and availability remain declarations, not authentication,
//! camera health, coverage, model admission, event authority or alert permission.

use std::collections::BTreeMap;
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget};
use fss_core::{CanonicalDecoder, CanonicalEncoder, ContentDigest, ContractError, DigestAlgorithm};
use fss_twin::image_tracking::TrackingAvailability;
use crate::{ChannelTransform, PreprocessProgram, ReplayCx, ScalarExecCx};
use crate::preprocess::{ResizeAspect, ResizeFilter};
use super::model_import::{ImportBudget, ImportLimits, WeightFloatPolicy};
use super::model_import::rgb::{ImportedRgbModel, RgbModelImportRequest};
use super::rgb_detections::{RgbDetectionBudget, RgbDetectionContract, RgbDetectionSpec};
use super::rgb_detections::pipeline::{RgbDetectionInput, RgbDetectionRun, RgbDetectionStep, RgbDetector};
use super::rgb_inference::{RgbModelSpec, RgbRunLimits, RgbSourceBinding};
use super::rgb_tracking::RgbFrameAdmission;

/// Complete portable envelope ceiling; no truncated source or result is accepted.
pub const MAX_RGB_EVIDENCE_BYTES: usize = 64 * 1024 * 1024;
const MAX_SOURCE: usize = 16 * 1024 * 1024;
const MAX_MASK: usize = 4_194_304;
const MAX_RECIPE: usize = 256 * 1024;

/// Independent byte ceilings, not an instruction to alter source or precision.
#[derive(Clone, Copy, Debug)]
pub struct RgbEvidenceLimits {
    /// Complete portable envelope bound, at most 64 MiB.
    pub maximum_bytes: usize,
    /// Per graph, weight file and encoded JPEG bound, at most 16 MiB each.
    pub maximum_source_bytes: usize,
}
impl Default for RgbEvidenceLimits {
    fn default() -> Self { Self { maximum_bytes: MAX_RGB_EVIDENCE_BYTES, maximum_source_bytes: MAX_SOURCE } }
}
impl RgbEvidenceLimits {
    fn validate(self) -> Result<(), RgbEvidenceError> {
        if !(1..=MAX_RGB_EVIDENCE_BYTES).contains(&self.maximum_bytes)
            || !(1..=MAX_SOURCE).contains(&self.maximum_source_bytes) { return Err(RgbEvidenceError::Limit); }
        Ok(())
    }
}

/// Refusal preserves all caller-owned sources and never returns fabricated tensors.
#[derive(Debug)]
pub enum RgbEvidenceError {
    /// Invalid or noncanonical recipe, unsupported version, or malformed framing.
    Format,
    /// Source, model, permission, admission, or replayed result identity differs.
    Mismatch,
    /// Byte/count/allocation limit exceeded; complete inputs are never top-k.
    Limit,
    /// Deterministic copy/hash/framing allowance exhausted.
    BudgetExceeded,
    /// Owner cancellation before a complete return.
    Cancelled,
    /// Shared canonical encoding was refused.
    Contract(ContractError),
    /// Existing import/decode/inference/head owner refused the actual computation.
    Computation(Box<dyn std::error::Error>),
}
impl From<ContractError> for RgbEvidenceError {
    fn from(error: ContractError) -> Self { Self::Contract(error) }
}
impl std::fmt::Display for RgbEvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Format => "invalid RGB evidence framing or recipe",
            Self::Mismatch => "RGB evidence source or replay mismatch",
            Self::Limit => "RGB evidence complete-input bound",
            Self::BudgetExceeded => "RGB evidence work exhausted",
            Self::Cancelled => "RGB evidence owner cancelled",
            Self::Contract(_) => "RGB evidence canonical contract refused",
            Self::Computation(_) => "RGB evidence computation refused",
        })
    }
}
impl std::error::Error for RgbEvidenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self { Self::Contract(e) => Some(e), Self::Computation(e) => Some(e.as_ref()), _ => None }
    }
}
fn computation<E: std::error::Error + 'static>(error: E) -> RgbEvidenceError {
    RgbEvidenceError::Computation(Box::new(error))
}
fn checkpoint(cx: &ReplayCx) -> Result<(), RgbEvidenceError> {
    cx.checkpoint("rgb-evidence:work").map_err(|_| RgbEvidenceError::Cancelled)
}

/// Cumulative byte-work allowance, separate from import/decode/inference/head work.
#[derive(Debug)]
pub struct RgbEvidenceBudget { remaining: u64, used: u64 }
impl RgbEvidenceBudget {
    /// Deterministic source copy/hash units, not time or whole-process memory.
    pub fn new(units: u64) -> Self { Self { remaining: units, used: 0 } }
    /// Charged work is never refunded by a failed operation.
    pub fn used(&self) -> u64 { self.used }
    /// Unspent caller allowance.
    pub fn remaining(&self) -> u64 { self.remaining }
    fn charge(&mut self, units: usize, cx: &ReplayCx) -> Result<(), RgbEvidenceError> {
        checkpoint(cx)?;
        let units = u64::try_from(units).map_err(|_| RgbEvidenceError::Limit)?;
        if units > self.remaining { return Err(RgbEvidenceError::BudgetExceeded); }
        self.remaining -= units; self.used += units; Ok(())
    }
}

/// Source-closed, immutable recipe and originals. Loading this type verifies byte
/// bindings only; `replay` must succeed before a restored inference is available.
#[derive(Debug)]
pub struct RgbEvidence {
    recipe: Vec<u8>, graph: Vec<u8>, weights: Vec<u8>, jpeg: Vec<u8>, mask: Vec<u8>,
    identity: ContentDigest,
}
impl RgbEvidence {
    /// Retain original sources for an already completed, opaque computation.
    /// Availability is preserved exactly; this method does not screen camera health.
    #[allow(clippy::too_many_arguments)]
    pub fn capture(imported: &ImportedRgbModel<'_>, head: &RgbDetectionContract,
        jpeg: &[u8], run: &RgbDetectionRun, admission: RgbFrameAdmission,
        limits: RgbEvidenceLimits, budget: &mut RgbEvidenceBudget, cx: &ReplayCx)
        -> Result<Self, RgbEvidenceError> {
        checkpoint(cx)?;
        let inference = run.inference();
        if imported.model().digest() != inference.model_digest() || head.spec().model != inference.model_digest()
            || run.report().contract_digest() != head.digest()
            || run.report().inference_identity() != inference.identity()
            || run.report().source() != inference.source() || admission.source() != inference.source() {
            return Err(RgbEvidenceError::Mismatch);
        }
        budget.charge(MAX_RECIPE, cx)?; // Bound metadata cloning/encoding before allocation.
        let recipe = Recipe { graph: imported.graph_digest(), weights: imported.weights_digest(),
            spec: imported.model().spec().clone(), float: imported.float_policy(), bindings: imported.bindings().clone(),
            head: head.spec().clone(), source: inference.source(),
            interpretation: inference.decode_receipt().interpretation,
            availability: admission.availability(), admission: admission.evidence().bytes(),
            expected: [imported.identity(), head.digest(), inference.identity(), inference.masked_digest(),
                inference.input_digest(), inference.output_digest(), run.report().digest()] };
        let bytes = wire::encode(&recipe)?;
        Self::from_parts(&bytes, imported.graph_source(), imported.weights_source(), jpeg, run.allowed(),
            ContentDigest::sha256(&bytes), limits, budget, cx)
    }

    /// Identity of the exact recipe, transitively binding every original source.
    /// It is deliberately not the hash of portable envelope framing.
    pub fn identity(&self) -> ContentDigest { self.identity }
    /// Original complete JPEG, including metadata, not reconstructed media.
    pub fn jpeg(&self) -> &[u8] { &self.jpeg }
    /// Original coded-grid permissions, unchanged by restore.
    pub fn allowed(&self) -> &[u8] { &self.mask }
    /// Original canonical graph bytes supplied to the importer.
    pub fn graph(&self) -> &[u8] { &self.graph }
    /// Original Safetensors file, retaining names, metadata, precision and layout.
    pub fn weights(&self) -> &[u8] { &self.weights }

    /// Encode a complete portable envelope after checking its allocation bound.
    pub fn encode(&self, limits: RgbEvidenceLimits, budget: &mut RgbEvidenceBudget, cx: &ReplayCx)
        -> Result<Vec<u8>, RgbEvidenceError> {
        let size = admit_parts(&self.recipe, &self.graph, &self.weights, &self.jpeg, &self.mask, limits)?;
        budget.charge(size, cx)?;
        let mut bytes = Vec::new(); bytes.try_reserve_exact(size).map_err(|_| RgbEvidenceError::Limit)?;
        bytes.extend_from_slice(b"FSSRGBE1");
        for part in [&self.recipe, &self.graph, &self.weights, &self.jpeg, &self.mask] {
            bytes.extend_from_slice(&(part.len() as u64).to_le_bytes());
            for chunk in part.chunks(4096) { checkpoint(cx)?; bytes.extend_from_slice(chunk); }
        }
        checkpoint(cx)?;
        Ok(bytes)
    }

    /// Restore complete sources with an independently supplied recipe identity.
    /// No embedded expected output is trusted as an executed result. Use `replay`.
    pub fn decode(bytes: &[u8], expected: ContentDigest, limits: RgbEvidenceLimits,
        budget: &mut RgbEvidenceBudget, cx: &ReplayCx) -> Result<Self, RgbEvidenceError> {
        limits.validate()?; budget.charge(48, cx)?;
        if bytes.len() > limits.maximum_bytes { return Err(RgbEvidenceError::Limit); }
        if bytes.get(..8) != Some(b"FSSRGBE1") { return Err(RgbEvidenceError::Format); }
        let mut at = 8;
        let mut parts = [&[][..]; 5];
        for part in &mut parts {
            let raw = bytes.get(at..at + 8).ok_or(RgbEvidenceError::Format)?;
            let length = usize::try_from(u64::from_le_bytes(raw.try_into().map_err(|_| RgbEvidenceError::Format)?))
                .map_err(|_| RgbEvidenceError::Limit)?;
            at += 8;
            let end = at.checked_add(length).ok_or(RgbEvidenceError::Limit)?;
            *part = bytes.get(at..end).ok_or(RgbEvidenceError::Format)?;
            at = end;
        }
        if at != bytes.len() { return Err(RgbEvidenceError::Format); }
        Self::from_parts(parts[0], parts[1], parts[2], parts[3], parts[4], expected, limits, budget, cx)
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(recipe: &[u8], graph: &[u8], weights: &[u8], jpeg: &[u8], mask: &[u8],
        expected: ContentDigest, limits: RgbEvidenceLimits, budget: &mut RgbEvidenceBudget, cx: &ReplayCx)
        -> Result<Self, RgbEvidenceError> {
        let size = admit_parts(recipe, graph, weights, jpeg, mask, limits)?;
        budget.charge(size.checked_mul(2).and_then(|n| n.checked_add(MAX_RECIPE)).ok_or(RgbEvidenceError::Limit)?, cx)?;
        if ContentDigest::sha256(recipe) != expected { return Err(RgbEvidenceError::Mismatch); }
        let r = wire::decode(recipe)?;
        if r.graph != ContentDigest::sha256(graph) || r.weights != ContentDigest::sha256(weights)
            || r.source.encoded_sha256 != ContentDigest::sha256(jpeg).bytes()
            || r.source.permission_mask != ContentDigest::sha256(mask).bytes() {
            return Err(RgbEvidenceError::Mismatch);
        }
        if mask.iter().any(|v| *v > 1) { return Err(RgbEvidenceError::Format); }
        let result = Self { identity: expected, recipe: copy(recipe, cx)?, graph: copy(graph, cx)?,
            weights: copy(weights, cx)?, jpeg: copy(jpeg, cx)?, mask: copy(mask, cx)? };
        checkpoint(cx)?; Ok(result)
    }

    /// Re-import original weights, decode original JPEG, apply original permissions,
    /// execute the original graph and head, then compare EVERY retained fingerprint.
    /// No latest model, supplied tensor shortcut, hidden fallback or ledger mutation.
    #[allow(clippy::too_many_arguments)]
    pub fn replay(&self, limits: RgbReplayLimits, work: &mut RgbEvidenceBudget,
        import: &mut ImportBudget, decoder: &mut DecodeBudget<'_>, head_work: &mut RgbDetectionBudget,
        cx: &ReplayCx, scalar: &ScalarExecCx) -> Result<ReplayedRgbEvidence, RgbEvidenceError> {
        work.charge(MAX_RECIPE, cx)?;
        scalar.checkpoint("rgb-evidence:replay").map_err(computation)?;
        let r = wire::decode(&self.recipe)?;
        let request = RgbModelImportRequest { graph: &self.graph, graph_digest: r.graph,
            weights: &self.weights, weights_digest: r.weights, spec: r.spec,
            float_policy: r.float, bindings: r.bindings };
        let imported = ImportedRgbModel::build(&request, limits.import, import, cx, scalar).map_err(computation)?;
        let head = RgbDetectionContract::new(r.head).map_err(computation)?;
        if imported.identity() != r.expected[0] || head.digest() != r.expected[1]
            || imported.model().digest() != head.spec().model { return Err(RgbEvidenceError::Mismatch); }
        let run = {
            let mut detector = RgbDetector::new(imported.model(), &head).map_err(computation)?;
            match detector.run_jpeg(RgbDetectionInput { bytes: &self.jpeg, allowed: &self.mask,
                source: r.source, interpretation: r.interpretation }, limits.run, decoder, head_work, scalar)
                .map_err(computation)? {
                RgbDetectionStep::Complete(run) => run,
                RgbDetectionStep::Pending(error) => return Err(computation(error)),
            }
        };
        let i = run.inference();
        if [i.identity(), i.masked_digest(), i.input_digest(), i.output_digest(), run.report().digest()]
            != r.expected[2..] { return Err(RgbEvidenceError::Mismatch); }
        let admission_digest = ContentDigest::new(DigestAlgorithm::Sha256, r.admission);
        let admission = RgbFrameAdmission::new(r.source, r.availability, admission_digest)
            .map_err(computation)?;
        checkpoint(cx)?; scalar.checkpoint("rgb-evidence:verified").map_err(computation)?;
        Ok(ReplayedRgbEvidence { evidence: self.identity, head, admission, run })
    }
}

/// Existing owner limits used by replay; successful allowances never change identities.
#[derive(Clone, Copy, Debug)]
pub struct RgbReplayLimits {
    /// Source importer bounds, independent of envelope framing limits.
    pub import: ImportLimits,
    /// Native decoder, preprocessing, scalar execution and complete output bounds.
    pub run: RgbRunLimits,
}
/// Actual recomputation, not a deserialized assertion that a model once ran.
#[derive(Debug)]
pub struct ReplayedRgbEvidence {
    evidence: ContentDigest, head: RgbDetectionContract, admission: RgbFrameAdmission, run: RgbDetectionRun,
}
impl ReplayedRgbEvidence {
    /// Independently matched source-closed recipe identity.
    pub fn evidence_identity(&self) -> ContentDigest { self.evidence }
    /// Reconstructed exact head vocabulary/semantics, useful to initialize a tracker.
    pub fn head(&self) -> &RgbDetectionContract { &self.head }
    /// Original availability declaration, not a newly measured camera-health finding.
    pub fn admission(&self) -> RgbFrameAdmission { self.admission }
    /// Native recomputed inference, owned permissions and complete head decisions.
    pub fn run(&self) -> &RgbDetectionRun { &self.run }
    /// Transfer the real results without leaving a borrowed model/source dependency.
    pub fn into_parts(self) -> (RgbDetectionRun, RgbDetectionContract, RgbFrameAdmission) {
        (self.run, self.head, self.admission)
    }
}

fn admit_parts(recipe: &[u8], graph: &[u8], weights: &[u8], jpeg: &[u8], mask: &[u8],
    limits: RgbEvidenceLimits) -> Result<usize, RgbEvidenceError> {
    limits.validate()?;
    if recipe.is_empty() || recipe.len() > MAX_RECIPE || mask.is_empty() || mask.len() > MAX_MASK
        || [graph, weights, jpeg].iter().any(|p| p.is_empty() || p.len() > limits.maximum_source_bytes) {
        return Err(RgbEvidenceError::Limit);
    }
    let size = [recipe, graph, weights, jpeg, mask].iter().try_fold(48_usize,
        |n, p| n.checked_add(p.len()).ok_or(RgbEvidenceError::Limit))?;
    if size > limits.maximum_bytes { return Err(RgbEvidenceError::Limit); }
    Ok(size)
}
fn copy(bytes: &[u8], cx: &ReplayCx) -> Result<Vec<u8>, RgbEvidenceError> {
    let mut result = Vec::new(); result.try_reserve_exact(bytes.len()).map_err(|_| RgbEvidenceError::Limit)?;
    for chunk in bytes.chunks(4096) { checkpoint(cx)?; result.extend_from_slice(chunk); }
    Ok(result)
}
struct Recipe {
    graph: ContentDigest, weights: ContentDigest, spec: RgbModelSpec, float: WeightFloatPolicy,
    bindings: BTreeMap<String, String>, head: RgbDetectionSpec, source: RgbSourceBinding,
    interpretation: ComponentInterpretation, availability: TrackingAvailability, admission: [u8; 32],
    // Imported source/recipe, head, inference, masked input, model input, tensors, detections.
    expected: [ContentDigest; 7],
}
mod wire;

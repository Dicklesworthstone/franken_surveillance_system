#![forbid(unsafe_code)]
//! Retained source-to-model execution using the existing pure-Rust scalar executor.
//!
//! An operator-authorized local bridge, not model-registry activation or alert policy. Source
//! uncertainty survives through the exact decoded-frame root. Outputs are uncalibrated model
//! tensors, never detections, corroboration, certified absence or external-effect authority.

use std::collections::BTreeMap;
use fss_core::{
    BatchId, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
    ContentDigest, ContractError, EvidenceDelta, LedgerAnchor, ObjectId, Plane,
};
use fss_model_ir::{ModelIrDecodeError, ModelIrError};
use fss_object::{ObjectError, ObjectManifest, SpoolError};
use fss_publication::{LocalPublicationError, SlotName};
use fss_tensor::{DType, Tensor, TensorError};
use crate::{ExecBudget, ExecError, ReferenceDeployment, ReferenceError, ReplayCx, ScalarExecCx, ScalarExecutor};
use super::recorded_decode::{RecordedDecodeError, RecordedDecodeRequest, RecordedFrame};

mod model;
pub use model::{MAX_RECORDED_MODEL_BYTES, RECORDED_MODEL_DOMAIN, RecordedModel};

/// Maximum input/intermediate tensor accounting admitted for one reference run.
pub const MAX_RUN_TENSOR_BYTES: usize = 256 * 1024 * 1024;
/// Maximum serialized output tensor set or normalized image input.
pub const MAX_RUN_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
/// Owner of the recorded execution receipt format.
pub const RECORDED_INFERENCE_DOMAIN: &str = "fss.recorded_model_run.v1";
/// Checkpoint before any result object is staged.
pub const STAGE_INFERENCE_STAGE: &str = "recorded_inference:stage";
/// Checkpoint after root publication, before final model-run authority.
pub const STAGE_INFERENCE_COMMIT: &str = "recorded_inference:commit";

/// Explicit refusal; no partial tensors or implicit fallback model are returned.
#[derive(Debug)]
pub enum ModelRunError {
    /// A configured or format allocation bound was exceeded.
    Limit,
    /// A frozen input, output, receipt, root or runtime identity does not match.
    Mismatch,
    /// A complete currently published run is absent.
    Unavailable,
    /// The bridge requires F32 ports and one exact full-resolution NCHW luma image input.
    UnsupportedInput,
    /// A parameter or output value is NaN or infinite.
    NonFinite,
    /// Parent cancellation occurred before final model-run publication.
    Cancelled,
    /// Canonical graph loading failed.
    GraphDecode(ModelIrDecodeError),
    /// The existing graph validator refused the model.
    Graph(ModelIrError),
    /// Tensor construction or materialization failed.
    Tensor(TensorError),
    /// The existing scalar executor refused or could not finish the run.
    Execution(ExecError),
    /// Retained source or decoded-frame recovery failed.
    Media(Box<RecordedDecodeError>),
    /// A shared semantic contract failed.
    Contract(ContractError),
    /// Deployment authority or custody failed.
    Reference(ReferenceError),
    /// The root manifest is invalid.
    Object(ObjectError),
    /// Local root-last publication failed.
    Publication(LocalPublicationError),
    /// Retained object reading or verification failed.
    Spool(SpoolError),
}
impl std::fmt::Display for ModelRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Limit => "recorded inference bound exceeded",
            Self::Mismatch => "recorded inference identity or provenance mismatch",
            Self::Unavailable => "completed recorded inference unavailable",
            Self::UnsupportedInput => "unsupported recorded model input contract",
            Self::NonFinite => "nonfinite recorded model parameter or result",
            Self::Cancelled => "recorded inference cancelled",
            Self::GraphDecode(_) | Self::Graph(_) => "recorded model graph refused",
            Self::Tensor(_) => "recorded model tensor refused",
            Self::Execution(_) => "recorded model execution refused",
            Self::Media(_) => "recorded model source unavailable",
            Self::Contract(_) => "recorded model contract invalid",
            Self::Reference(_) | Self::Object(_) | Self::Publication(_) | Self::Spool(_) => "recorded model storage refused",
        })
    }
}
impl std::error::Error for ModelRunError {}
macro_rules! conversion {
    ($source:ty, $variant:ident) => {
        impl From<$source> for ModelRunError {
            fn from(error: $source) -> Self { Self::$variant(error) }
        }
    };
}
conversion!(ModelIrDecodeError, GraphDecode);
conversion!(ModelIrError, Graph);
conversion!(TensorError, Tensor);
conversion!(ExecError, Execution);
impl From<RecordedDecodeError> for ModelRunError {
    fn from(error: RecordedDecodeError) -> Self { Self::Media(Box::new(error)) }
}
conversion!(ContractError, Contract);
conversion!(ReferenceError, Reference);
conversion!(ObjectError, Object);
conversion!(LocalPublicationError, Publication);
conversion!(SpoolError, Spool);
type Result<T> = std::result::Result<T, ModelRunError>;

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage).map_err(|_| ModelRunError::Cancelled)
}
fn hex(d: ContentDigest) -> String { d.bytes().iter().map(|b| format!("{b:02x}")).collect() }
fn slot(id: ContentDigest) -> Result<SlotName> {
    SlotName::parse(&format!("mi-{}", hex(id))).map_err(|_| ModelRunError::Mismatch)
}
fn batch_id(id: ContentDigest) -> Result<BatchId> {
    Ok(BatchId::parse(format!("batch:model-run:{}", hex(id)))?)
}

/// Source fingerprint of this execution bridge, scalar/preprocess code and tensor kernels.
/// This is not a binary/toolchain qualification receipt; changed code requires explicit rerun.
pub fn executor_profile_digest() -> ContentDigest {
    let sources: &[&[u8]] = &[
        include_bytes!("mod.rs"), include_bytes!("model.rs"),
        include_bytes!("../../scalar_executor.rs"),
        include_bytes!("../../../../fss-tensor/src/tensor.rs"),
        include_bytes!("../../../../fss-tensor/src/dtype.rs"),
        include_bytes!("../../../../fss-tensor/src/shape.rs"),
        include_bytes!("../../../../fss-tensor/src/storage.rs"),
        include_bytes!("../../../../fss-tensor/src/stride.rs"),
        include_bytes!("../../../../fss-tensor/src/view.rs"),
        include_bytes!("../../../../fss-model-ir/src/shape_inference.rs"),
    ];
    let mut e = CanonicalEncoder::new(); e.text("fss.recorded_executor_source_profile.v1");
    for source in sources { e.digest(ContentDigest::sha256(source)); }
    ContentDigest::sha256(&e.finish())
}

fn run_identity(model: ContentDigest, frame: ContentDigest, runtime: ContentDigest) -> ContentDigest {
    let mut e = CanonicalEncoder::new(); e.text("fss.recorded_model_run_key.v1");
    e.digest(model); e.digest(frame); e.digest(runtime);
    ContentDigest::sha256(&e.finish())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Receipt {
    model: ContentDigest,
    frame: ContentDigest,
    frame_receipt: ContentDigest,
    source_anchor: LedgerAnchor,
    runtime: ContentDigest,
    input: ContentDigest,
    output: ContentDigest,
    macs: u64,
    allocated: u64,
    nodes: u64,
}
impl Receipt {
    fn identity(&self) -> ContentDigest {
        run_identity(self.model, self.frame, self.runtime)
    }
    fn encoded(&self) -> Result<Vec<u8>> {
        let mut e = CanonicalEncoder::new(); e.bytes(b"FSSMRUN1"); e.u32(1); e.text(RECORDED_INFERENCE_DOMAIN);
        e.digest(self.model); e.digest(self.frame); e.digest(self.frame_receipt);
        self.source_anchor.encode_canonical(&mut e); e.digest(self.runtime);
        e.digest(self.input); e.digest(self.output); e.u64(self.macs); e.u64(self.allocated); e.u64(self.nodes);
        Ok(e.finish_checked()?)
    }
    fn decode(bytes: &[u8], expected: ContentDigest) -> Result<Self> {
        if bytes.len() > 4096 || ContentDigest::sha256(bytes) != expected { return Err(ModelRunError::Mismatch); }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != b"FSSMRUN1" || d.u32()? != 1 || d.text()? != RECORDED_INFERENCE_DOMAIN {
            return Err(ModelRunError::Mismatch);
        }
        let value = Self {
            model: d.digest()?, frame: d.digest()?, frame_receipt: d.digest()?,
            source_anchor: LedgerAnchor::decode_canonical(&mut d)?, runtime: d.digest()?,
            input: d.digest()?, output: d.digest()?, macs: d.u64()?, allocated: d.u64()?, nodes: d.u64()?,
        };
        d.ensure_finished()?;
        if value.runtime != executor_profile_digest() || value.allocated > MAX_RUN_TENSOR_BYTES as u64
            || value.nodes > fss_model_ir::MAX_MODEL_IR_ITEMS as u64 || value.encoded()? != bytes
        { return Err(ModelRunError::Mismatch); }
        Ok(value)
    }
    fn manifest(&self) -> Result<ObjectManifest> {
        let metadata = ContentDigest::sha256(&self.encoded()?);
        let mut children = vec![self.model, self.frame, self.frame_receipt, self.input, self.output];
        children.sort_unstable(); children.dedup(); children.retain(|d| *d != metadata);
        Ok(ObjectManifest::new(slot(self.identity())?.as_str(), children, Some(metadata))?)
    }
    fn delta(&self, frame: &RecordedFrame, root: ContentDigest) -> Result<EvidenceDelta> {
        let id = hex(self.identity());
        Ok(EvidenceDelta {
            delta_id: format!("delta:model-run:{id}"), family: "model_invocation_receipt".to_owned(),
            object_id: ObjectId::parse(format!("object:model-run:{id}"))?,
            prior_generation: None, new_generation: 1, validity: frame.receipt().capsule().capture,
            plane: Plane::Cognition, payload_digest: ContentDigest::sha256(&self.encoded()?),
            witness_digest: Some(root), operation_id: None,
        })
    }
}

fn tensor_bytes(tensors: &BTreeMap<String, Tensor>, generation: fss_core::Generation) -> Result<Vec<u8>> {
    if tensors.len() > 256 { return Err(ModelRunError::Limit); }
    let mut size = 64_usize;
    for (name, tensor) in tensors {
        if tensor.dtype() != DType::F32 || tensor.generation() != generation { return Err(ModelRunError::Mismatch); }
        size = size.checked_add(name.len() + 48 + tensor.shape().rank() * 8)
            .and_then(|n| tensor.shape().size_bytes(DType::F32).ok().and_then(|v| n.checked_add(v)))
            .ok_or(ModelRunError::Limit)?;
    }
    if size > MAX_RUN_OUTPUT_BYTES { return Err(ModelRunError::Limit); }
    let mut e = CanonicalEncoder::new(); e.bytes(b"FSSRTEN1"); e.u32(1); e.u64(generation.get()); e.u64(tensors.len() as u64);
    for (name, tensor) in tensors {
        e.text(name); e.u8(DType::F32.type_tag()); e.u64(tensor.shape().rank() as u64);
        for &dim in tensor.shape().dims() { e.u64(dim as u64); }
        let values = tensor.to_vec::<f32>()?; e.u64(values.len() as u64);
        for value in values {
            if !value.is_finite() { return Err(ModelRunError::NonFinite); }
            e.u32(value.to_bits());
        }
    }
    Ok(e.finish_checked()?)
}

fn decode_outputs(bytes: &[u8], model: &RecordedModel) -> Result<BTreeMap<String, Vec<f32>>> {
    if bytes.len() > MAX_RUN_OUTPUT_BYTES { return Err(ModelRunError::Limit); }
    let mut d = CanonicalDecoder::new(bytes);
    if d.bytes()? != b"FSSRTEN1" || d.u32()? != 1 || d.u64()? != model.graph().generation().get()
        || d.u64()? != model.graph().outputs().len() as u64
    { return Err(ModelRunError::Mismatch); }
    let mut outputs = BTreeMap::new();
    let mut previous: Option<String> = None;
    for _ in model.graph().outputs() {
        let name = d.text()?.to_owned();
        if previous.as_ref().is_some_and(|p| p >= &name) || d.u8()? != DType::F32.type_tag() {
            return Err(ModelRunError::Mismatch);
        }
        let port = model.graph().find_output(&name).ok_or(ModelRunError::Mismatch)?;
        if d.u64()? != port.rank() as u64 { return Err(ModelRunError::Mismatch); }
        for &dimension in port.shape().dims() {
            if d.u64()? != dimension as u64 { return Err(ModelRunError::Mismatch); }
        }
        let count = usize::try_from(d.u64()?).map_err(|_| ModelRunError::Limit)?;
        if count != port.shape().num_elements()? || count > d.remaining() / 4 { return Err(ModelRunError::Mismatch); }
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            let value = f32::from_bits(d.u32()?);
            if !value.is_finite() { return Err(ModelRunError::NonFinite); }
            values.push(value);
        }
        previous = Some(name.clone()); outputs.insert(name, values);
    }
    d.ensure_finished()?;
    Ok(outputs)
}

fn execute(frame: &RecordedFrame, model: &RecordedModel, budget: ExecBudget, exec_cx: &ScalarExecCx)
    -> Result<(Receipt, Vec<u8>, Vec<u8>)> {
    exec_cx.checkpoint("recorded-model:bind")?;
    let inputs = model.bind(frame, budget)?;
    let image = inputs.iter().find(|(name, _)| name == model.frame_input()).ok_or(ModelRunError::Mismatch)?;
    let input = tensor_bytes(&BTreeMap::from([(image.0.clone(), image.1.clone())]), model.graph().generation())?;
    let outcome = ScalarExecutor::run(model.graph(), &inputs, budget, exec_cx)?;
    let output = tensor_bytes(outcome.outputs(), model.graph().generation())?;
    exec_cx.checkpoint("recorded-model:complete")?;
    let receipt = Receipt {
        model: model.digest(), frame: frame.publication_root(), frame_receipt: frame.receipt().digest()?,
        source_anchor: frame.authority_anchor().clone(), runtime: executor_profile_digest(),
        input: ContentDigest::sha256(&input), output: ContentDigest::sha256(&output),
        macs: outcome.executed_macs(), allocated: outcome.allocated_bytes() as u64, nodes: outcome.nodes_executed() as u64,
    };
    Ok((receipt, input, output))
}

/// Completed model tensors with exact source, preprocessing, parameter and execution provenance.
/// Fields are private so an unverified result cannot be constructed as a retained run.
#[derive(Clone, Debug)]
pub struct RecordedInference {
    receipt: Receipt,
    model: RecordedModel,
    output_bytes: Vec<u8>,
    outputs: BTreeMap<String, Vec<f32>>,
    authority_anchor: LedgerAnchor,
}
impl RecordedInference {
    /// Computes the existing exact run key without executing or publishing a model.
    /// The key binds the frozen model, verified frame root and current executor source profile.
    /// It is a lookup identity, not proof that the run is complete or currently retrievable.
    #[must_use]
    pub fn identity_for(frame: &RecordedFrame, model: &RecordedModel) -> ContentDigest {
        run_identity(model.digest(), frame.publication_root(), executor_profile_digest())
    }

    /// Executes a frozen model on an already retained decoded frame and publishes its results.
    ///
    /// Uses only the existing scalar executor. Parent cancellation is checked at composition
    /// boundaries; `exec_cx` controls cancellation within execution. There are no detached workers.
    /// A cut between root publication and the final delta is incomplete, and an exact retry can
    /// finish it. Admission budgets are not model identity and do not duplicate successful runs.
    /// Completed runs are revalidated from custody without another numeric execution; their
    /// receipt accounting describes the original run. A corrupt completed run is refused, never
    /// overwritten by a retry. Reopening remains subject to the caller's tensor ceiling.
    pub fn run_and_publish(
        deployment: &mut ReferenceDeployment, source: &RecordedDecodeRequest, model: &RecordedModel,
        budget: ExecBudget, exec_cx: &ScalarExecCx, cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx, "recorded_inference:source")?;
        if budget.max_bytes == 0 || budget.max_bytes > MAX_RUN_TENSOR_BYTES {
            return Err(ModelRunError::Limit);
        }
        exec_cx.checkpoint("recorded-model:bind")?;
        let frame = RecordedFrame::open(deployment, source, cx)?;
        let identity = Self::identity_for(&frame, model);
        let completion = batch_id(identity)?;
        if deployment.ledger().batches().iter().any(|batch| batch.batch_id == completion) {
            // A completion record is not a cache miss when its custody is damaged. Propagate
            // verification failure rather than restaging bytes or substituting another result.
            let existing = Self::open(deployment, identity, source, cx)?;
            if existing.allocated_tensor_bytes() > budget.max_bytes as u64 {
                return Err(ModelRunError::Limit);
            }
            return Ok(existing);
        }
        let (receipt, input, output) = execute(&frame, model, budget, exec_cx)?;
        let outputs = decode_outputs(&output, model)?;
        let encoded = receipt.encoded()?;
        let manifest = receipt.manifest()?;
        let target = slot(receipt.identity())?;
        let existing_root = deployment.publisher().root(&target).map(|root| root.root);
        if existing_root.is_some_and(|root| root != manifest.root()) {
            return Err(ModelRunError::Mismatch);
        }
        for bytes in [model.encoded(), input.as_slice(), output.as_slice(), encoded.as_slice()] {
            checkpoint(cx, STAGE_INFERENCE_STAGE)?;
            let digest = deployment.publisher_mut().stage_object(bytes)?;
            deployment.publisher_mut().verify_object(digest)?;
        }
        // `stage_manifest` refuses a visible slot by design; an exact retry or a resume after the
        // root-to-receipt interruption finds the identical root already published and only owes
        // the ledger batch (append_batch is idempotent by batch_id).
        // A crash/cancellation can leave an identical visible root without its completion
        // delta. Do not restage that slot: the publisher correctly refuses visible slots.
        // publish_and_commit revalidates the existing closure and finishes any owed linkage.
        if existing_root.is_none() {
            deployment.publisher_mut().stage_manifest(&target, &manifest)?;
        }
        deployment.publish_and_commit(&target, &manifest, frame.receipt().capsule().capture, cx)?;
        checkpoint(cx, STAGE_INFERENCE_COMMIT)?;
        let delta = receipt.delta(&frame, manifest.root())?;
        let mut children = manifest.children().to_vec(); children.push(manifest.root());
        let authority_anchor = deployment.append_batch(batch_id(receipt.identity())?, vec![delta], children, cx)?;
        cx.checkpoint_post_commit("recorded_inference:complete");
        Ok(Self { receipt, model: model.clone(), output_bytes: output, outputs, authority_anchor })
    }

    /// Restores a completed run from storage, including its model, without a model-file path.
    /// Source selection is explicit and revalidated; an identity cannot be rebound to another frame.
    pub fn open(
        deployment: &ReferenceDeployment, identity: ContentDigest, source: &RecordedDecodeRequest, cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx, "recorded_inference:open")?;
        let target = batch_id(identity)?;
        let batch = deployment.ledger().batches().iter().find(|b| b.batch_id == target).ok_or(ModelRunError::Unavailable)?;
        if batch.deltas.len() != 1 { return Err(ModelRunError::Mismatch); }
        let delta = &batch.deltas[0];
        let bytes = deployment.publisher().spool().read(delta.payload_digest)?;
        let receipt = Receipt::decode(&bytes, delta.payload_digest)?;
        if receipt.identity() != identity { return Err(ModelRunError::Mismatch); }
        let frame = RecordedFrame::open(deployment, source, cx)?;
        if frame.publication_root() != receipt.frame || frame.receipt().digest()? != receipt.frame_receipt
            || *frame.authority_anchor() != receipt.source_anchor
        { return Err(ModelRunError::Mismatch); }
        let manifest = receipt.manifest()?;
        if *delta != receipt.delta(&frame, manifest.root())? { return Err(ModelRunError::Mismatch); }
        let mut children = manifest.children().to_vec(); children.push(manifest.root()); children.sort_unstable(); children.dedup();
        if batch.children != children
            || deployment.publisher().root(&slot(identity)?).is_none_or(|r| r.root != manifest.root())
            || deployment.publisher().spool().read(manifest.root())? != manifest.canonical_bytes()
        { return Err(ModelRunError::Mismatch); }
        let model = RecordedModel::decode(&deployment.publisher().spool().read(receipt.model)?, receipt.model)?;
        let input = deployment.publisher().spool().read(receipt.input)?;
        if input.len() > MAX_RUN_OUTPUT_BYTES || ContentDigest::sha256(&input) != receipt.input { return Err(ModelRunError::Mismatch); }
        let bound = model.bind(&frame, ExecBudget::new(u64::MAX, MAX_RUN_TENSOR_BYTES))?;
        let image = bound.iter().find(|(name, _)| name == model.frame_input()).ok_or(ModelRunError::Mismatch)?;
        if tensor_bytes(&BTreeMap::from([(image.0.clone(), image.1.clone())]), model.graph().generation())? != input {
            return Err(ModelRunError::Mismatch);
        }
        let output_bytes = deployment.publisher().spool().read(receipt.output)?;
        if ContentDigest::sha256(&output_bytes) != receipt.output { return Err(ModelRunError::Mismatch); }
        let outputs = decode_outputs(&output_bytes, &model)?;
        checkpoint(cx, "recorded_inference:read_complete")?;
        Ok(Self { receipt, model, output_bytes, outputs, authority_anchor: batch.new_anchor.clone() })
    }

    /// Re-executes the retained model and compares exact tensor bytes and numeric accounting.
    /// Custody-only `open` does not make this independent reproducibility claim.
    pub fn verify_by_replay(
        &self, deployment: &ReferenceDeployment, source: &RecordedDecodeRequest,
        budget: ExecBudget, exec_cx: &ScalarExecCx, cx: &ReplayCx,
    ) -> Result<()> {
        let restored = Self::open(deployment, self.identity(), source, cx)?;
        if restored.receipt != self.receipt || restored.output_bytes != self.output_bytes { return Err(ModelRunError::Mismatch); }
        let frame = RecordedFrame::open(deployment, source, cx)?;
        let (receipt, _, output) = execute(&frame, &restored.model, budget, exec_cx)?;
        if receipt != self.receipt || output != self.output_bytes { return Err(ModelRunError::Mismatch); }
        checkpoint(cx, "recorded_inference:replay_complete")
    }
    /// Exact immutable run identity.
    #[must_use]
    pub fn identity(&self) -> ContentDigest { self.receipt.identity() }
    /// Retained graph/parameter/preprocessing object.
    #[must_use]
    pub fn model(&self) -> &RecordedModel { &self.model }
    /// Source decoded-frame graph root.
    #[must_use]
    pub fn frame_root(&self) -> ContentDigest { self.receipt.frame }
    /// Uncalibrated F32 outputs; shapes are declared in the retained model's output ports.
    #[must_use]
    pub fn outputs(&self) -> &BTreeMap<String, Vec<f32>> { &self.outputs }
    /// Canonical typed tensor-set bytes for exact export or comparison.
    #[must_use]
    pub fn output_bytes(&self) -> &[u8] { &self.output_bytes }
    /// Canonical execution receipt for audit/export.
    pub fn receipt_bytes(&self) -> Result<Vec<u8>> { self.receipt.encoded() }
    /// Exact final model-run completion anchor.
    #[must_use]
    pub fn authority_anchor(&self) -> &LedgerAnchor { &self.authority_anchor }
    /// Successful executor MAC accounting, not CPU time or a performance claim.
    #[must_use]
    pub fn executed_macs(&self) -> u64 { self.receipt.macs }
    /// Executor tensor accounting, not total process peak memory.
    #[must_use]
    pub fn allocated_tensor_bytes(&self) -> u64 { self.receipt.allocated }
}

#[cfg(test)]
mod tests;

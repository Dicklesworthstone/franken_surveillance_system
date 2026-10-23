#![forbid(unsafe_code)]
//! Native reference activity from completed recorded imports, never caller-supplied pixels.
//!
//! The caller explicitly selects two JPEG segments, the sensor/stream, immutable package pin,
//! policy, job and original execution allowance. The retained import owner proves source custody
//! and current deletion status before either native decode. The complete six source roles are
//! published before the existing result/receipt retention owner runs. Their manifest names the
//! original import manifest as metadata, preserving the canonical deletion walk's ancestry.
//!
//! This v1 computation has no privacy-mask binding. A sensor with any current retained mask
//! policy is therefore refused before source reads, never decoded around its policy. The result
//! remains reference-only, uncalibrated and incapable of certifying presence, absence or effects.

use std::fmt;

use fss_codec_mjpeg::color::{RgbDecodeLimits, decode_rgb};
use fss_codec_mjpeg::{DecodeBudget, DecodeError};
use fss_core::{
    CanonicalEncode, CaptureInterval, ContentDigest, ContractError, DigestAlgorithm, LedgerAnchor,
};
use fss_object::{ObjectError, ObjectManifest, SpoolError};
use fss_publication::{LocalPublicationState, SlotName};

use super::privacy_mask::{MaskBinding, PrivacyMaskError, current_mask};
use super::recorded_decode::{
    RecordedDecodeError, source_capsule, validate_limits, verify_custody,
};
use super::retained::SourceReadBudget;
use super::{FileIngestError, RetainedFileImport, RetainedReadLimits, VerifiedChunkCache};
use crate::activity_replay::{ActivityReplayLimits, ActivityReplayPlan};
use crate::executor_activity::{
    ActivityExecutorModel, ActivityFrameBinding, ExecutorActivityError, MAX_ACTIVITY_MODEL_PIXELS,
    RetainedExecutorResult, retain_executor_result, retention_slot, rgb_decode_receipt_bytes,
};
use crate::{ReferenceDeployment, ReferenceError, ReplayCx, ScalarExecCx};

/// Checkpoint before import admission or any source read.
pub const STAGE_ACTIVITY_SOURCE: &str = "recorded_activity:source";
/// Checkpoint after all computation and current-source revalidation, before any publication.
pub const STAGE_ACTIVITY_BEFORE_PUBLISH: &str = "recorded_activity:before_publish";
/// Checkpoint after complete source-role publication and before result retention.
pub const STAGE_ACTIVITY_RESULT: &str = "recorded_activity:result";

/// A fully explicit computation over immutable imported segments.
#[derive(Clone, Debug)]
pub struct RecordedActivityRequest {
    /// Exact completed import; its original path is neither needed nor reopened.
    pub import_identity: ContentDigest,
    /// Earlier source segment in the same import.
    pub reference_segment: usize,
    /// Evaluated source segment, strictly after the reference.
    pub segment: usize,
    /// Independently pinned SHA-256 of the committed built-in package archive.
    pub expected_package_sha256: ContentDigest,
    /// Independent source identities and exact original native invocation configuration.
    pub plan: ActivityReplayPlan,
}

/// Finite source, native compute and publication admission for one pair.
#[derive(Clone, Copy, Debug)]
pub struct RecordedActivityLimits {
    /// Existing retained reader's per-file, per-chunk and assembled-segment ceilings.
    pub read: RetainedReadLimits,
    /// Complete native JPEG and RGB-output ceilings for each of the two frames.
    pub decode: RgbDecodeLimits,
    /// Shared nonrefillable original-chunk/origin-proof allowance, including the fresh final read.
    /// Existing import/capsule metadata reads retain their deployment and canonical codec bounds.
    pub max_source_read_bytes: u64,
    /// Shared native JPEG work allowance for both frames.
    pub max_decode_work: u64,
    /// Six role payloads, result, invocation JSON and both native manifests, including repeated
    /// roles. Already retained import metadata is reused and excluded. Admission precedes the
    /// first write; this is not a count of physical writes or publication-read traffic.
    pub max_staged_bytes: u64,
    /// Maximum committed batches admitted before any metadata/capsule history scans.
    pub max_history_batches: usize,
    /// Maximum total delta/child entries in that admitted history.
    pub max_history_entries: usize,
}

impl Default for RecordedActivityLimits {
    fn default() -> Self {
        Self {
            read: RetainedReadLimits::default(),
            decode: ActivityReplayLimits::default().decode,
            max_source_read_bytes: 128 * 1024 * 1024,
            max_decode_work: 20_000_000,
            max_staged_bytes: 64 * 1024 * 1024,
            max_history_batches: 256,
            max_history_entries: 16_384,
        }
    }
}

/// Complete durable handles. A retained abstention remains an abstention, not a scored belief.
#[derive(Debug)]
pub struct RecordedActivityReceipt {
    /// Existing canonical result, invocation receipt, published root and cognition anchor.
    pub retained: RetainedExecutorResult,
    /// Explicit source slot to pass to the independent cold activity verifier.
    pub source_slot: SlotName,
    /// Complete source-role publication, metadata-linked to the original import manifest.
    pub source_root: ContentDigest,
    /// Exact original recording and its completed publication.
    pub import_identity: ContentDigest,
    /// Original import's root, not the later role publication.
    pub import_root: ContentDigest,
    /// Earlier original segment.
    pub reference_segment: usize,
    /// Evaluated original segment.
    pub segment: usize,
    /// Exact original reference capsule, independently supplied to cold verification.
    pub reference_capsule: ContentDigest,
    /// Exact original evaluated capsule.
    pub frame_capsule: ContentDigest,
    /// Full independent invocation configuration; nothing is reconstructed from the score.
    pub plan: ActivityReplayPlan,
    /// Verified whole archive and manifest package pins.
    pub package_sha256: ContentDigest,
    /// Package manifest named by the native invocation receipt.
    pub package_root: ContentDigest,
    /// Charged original chunk/origin-proof reads, including final source revalidation.
    pub source_read_bytes: u64,
    /// Actual native JPEG work for both frames; preprocessing/execution retain their own bounds.
    pub decode_work: u64,
    /// Complete publication input admitted before writing (not physical write traffic).
    pub staged_input_bytes: u64,
    /// Current canonical anchor after all successful publication and result retention.
    pub final_anchor: LedgerAnchor,
}

/// No refusal is converted to a quiet score. Publication failure may leave staged objects or a
/// durable source/result root; retry the identical request or use canonical recovery, never erase it.
#[derive(Debug)]
pub enum RecordedActivityError {
    /// Invalid independently selected request or mismatching original source identities.
    Selection(&'static str),
    /// This exact owner admits completed JPEG/MJPEG imports only.
    UnsupportedMedia,
    /// The independent archive pin differs from the verified committed package.
    PackagePin,
    /// A source, history, native-frame or complete-publication allowance was exhausted.
    Limit(&'static str),
    /// The original source/capsule or immutable publication changed or disagrees.
    SourceChanged,
    /// Current privacy policy is unavailable or cannot be honored by this computation profile.
    Privacy(PrivacyMaskError),
    /// Original import custody/deletion/origin verification refused.
    Source(Box<FileIngestError>),
    /// Canonical imported capsule lookup refused.
    Capsule(Box<RecordedDecodeError>),
    /// Native JPEG decode refused; no derivative was staged.
    Decode(DecodeError),
    /// Package, preprocessing, native invocation or existing result retention refused.
    Execution(ExecutorActivityError),
    /// Canonical source encoding refused.
    Contract(ContractError),
    /// Canonical role-manifest construction refused.
    Object(ObjectError),
    /// Existing role custody is damaged; an exact retry does not repair it.
    Spool(SpoolError),
    /// Source publication or ledger append refused.
    Publication(Box<ReferenceError>),
    /// Cancellation observed at an owned boundary, without claiming rollback after publication.
    Cancelled,
}

impl RecordedActivityError {
    /// Registered stable identity; underlying privacy, deletion and package identities survive.
    #[must_use]
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Privacy(error) => error.stable_id(),
            Self::Source(error) => error.stable_id().unwrap_or("ERR-RECORDED-ACTIVITY-001"),
            Self::Capsule(error) => error.stable_id(),
            Self::PackagePin => "ERR-MODEL-PACKAGE-DIGEST-001",
            Self::Execution(ExecutorActivityError::Package(error)) => error.stable_id(),
            Self::UnsupportedMedia => "ERR-DECODE-UNSUPPORTED-MEDIA-001",
            Self::Limit(_) | Self::Decode(DecodeError::Limit | DecodeError::BudgetExhausted) => {
                "ERR-RECORDED-ACTIVITY-BOUNDS-001"
            }
            _ => "ERR-RECORDED-ACTIVITY-001",
        }
    }
}
impl fmt::Display for RecordedActivityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selection(field) => write!(f, "invalid recorded activity selection: {field}"),
            Self::UnsupportedMedia => f.write_str("recorded activity requires an exact completed JPEG/MJPEG import"),
            Self::PackagePin => f.write_str("recorded activity package differs from the independent archive pin"),
            Self::Limit(field) => write!(f, "recorded activity {field} allowance exhausted"),
            Self::SourceChanged => f.write_str("recorded activity original source or publication changed; no substitute is permitted"),
            Self::Privacy(error) => write!(f, "recorded activity privacy: {error}"),
            Self::Source(error) => write!(f, "recorded activity source: {error}"),
            Self::Capsule(error) => write!(f, "recorded activity capsule: {error}"),
            Self::Decode(error) => write!(f, "recorded activity JPEG: {error}"),
            Self::Execution(error) => write!(f, "recorded activity execution or retention: {error}"),
            Self::Contract(error) => write!(f, "recorded activity contract: {error}"),
            Self::Object(error) => write!(f, "recorded activity manifest: {error}"),
            Self::Spool(error) => write!(f, "recorded activity existing custody: {error}"),
            Self::Publication(error) => write!(f, "recorded activity publication: {error}"),
            Self::Cancelled => f.write_str("recorded activity cancelled; already committed custody is preserved"),
        }
    }
}
impl std::error::Error for RecordedActivityError {}
macro_rules! conversion {
    ($source:ty, $variant:ident) => {
        impl From<$source> for RecordedActivityError {
            fn from(error: $source) -> Self {
                Self::$variant(error.into())
            }
        }
    };
}
conversion!(PrivacyMaskError, Privacy);
conversion!(FileIngestError, Source);
conversion!(RecordedDecodeError, Capsule);
conversion!(DecodeError, Decode);
conversion!(ExecutorActivityError, Execution);
conversion!(ContractError, Contract);
conversion!(ObjectError, Object);
conversion!(SpoolError, Spool);
conversion!(ReferenceError, Publication);
type Result<T> = std::result::Result<T, RecordedActivityError>;
type Error = RecordedActivityError;

fn checkpoint(cx: &ReplayCx, scalar: &ScalarExecCx, stage: &'static str) -> Result<()> {
    if cx.checkpoint(stage).is_err() || scalar.checkpoint(stage).is_err() {
        cx.drain_and_finalize();
        scalar.drain_and_finalize();
        return Err(Error::Cancelled);
    }
    Ok(())
}

fn admit(
    deployment: &ReferenceDeployment,
    request: &RecordedActivityRequest,
    limits: RecordedActivityLimits,
) -> Result<()> {
    if request.import_identity.algorithm() != DigestAlgorithm::Sha256
        || request.import_identity.bytes() == [0; 32]
        || request.expected_package_sha256.algorithm() != DigestAlgorithm::Sha256
        || request.expected_package_sha256.bytes() == [0; 32]
        || request.reference_segment >= request.segment
    {
        return Err(Error::Selection("import, package or segment order"));
    }
    if request.plan.job_id.is_empty()
        || request.plan.job_id.len() > 128
        || !request
            .plan
            .job_id
            .bytes()
            .all(|byte| byte.is_ascii_graphic())
    {
        return Err(Error::Selection("job identity"));
    }
    validate_limits(limits.decode.frame)?;
    if limits.decode.frame.maximum_pixels > MAX_ACTIVITY_MODEL_PIXELS
        || limits.decode.maximum_output_bytes == 0
        || limits.decode.maximum_output_bytes > 3 * MAX_ACTIVITY_MODEL_PIXELS
        || limits.read.max_chunk_bytes == 0
        || limits.read.max_chunk_bytes > 16 * 1024 * 1024
        || limits.read.max_segment_bytes == 0
        || limits.read.max_segment_bytes > 16 * 1024 * 1024
    {
        return Err(Error::Limit("source or native-frame ceiling"));
    }
    let batches = deployment.ledger().batches();
    if batches.len() > limits.max_history_batches {
        return Err(Error::Limit("history batches"));
    }
    let mut entries = 0_usize;
    for batch in batches {
        entries = entries
            .checked_add(batch.deltas.len())
            .and_then(|n| n.checked_add(batch.children.len()))
            .filter(|n| *n <= limits.max_history_entries)
            .ok_or(Error::Limit("history entries"))?;
    }
    Ok(())
}

fn refuse_mask(deployment: &ReferenceDeployment, plan: &ActivityReplayPlan) -> Result<()> {
    if !matches!(
        current_mask(deployment, &plan.sensor_id)?,
        MaskBinding::NoPolicy
    ) {
        return Err(PrivacyMaskError::UnmaskedAccessRefused.into());
    }
    Ok(())
}

fn slot(
    result: ContentDigest,
    frame_capsule: ContentDigest,
    reference_capsule: ContentDigest,
    import_manifest: ContentDigest,
) -> Result<SlotName> {
    // The native result binds reference pixels, not the identity of the earlier reference
    // capsule. Distinct earlier exposures may legitimately contain identical bytes. Keep their
    // source publications distinct while allowing the existing result/receipt to be shared.
    let mut selection = vec![result, frame_capsule, reference_capsule, import_manifest];
    selection.sort_unstable();
    selection.dedup();
    let identity = ObjectManifest::new("recorded-activity-selection", selection, None)?.root();
    let hex: String = identity
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    SlotName::parse(&format!("xi-{hex}")).map_err(|_| Error::Selection("source slot"))
}

/// Produce and retain one actual native computation from two exact imported JPEG segments.
///
/// Requested admission, source, decode and compute allowances are checked before staging. Storage
/// I/O or capacity failure can still occur during publication. Source roles are committed
/// first; an interruption later can leave this complete source root, never a success receipt.
/// An identical retry verifies existing role custody, then uses the existing idempotent result
/// retention owner. It never restages over corrupt published bytes. The source and decode
/// allowances are shared across the pair, and source allowance also pays for a fresh final read.
/// Cancellation is cooperative at bounded native calls and publication boundaries.
pub fn produce_recorded_activity(
    deployment: &mut ReferenceDeployment,
    request: RecordedActivityRequest,
    limits: RecordedActivityLimits,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> Result<RecordedActivityReceipt> {
    checkpoint(cx, scalar, STAGE_ACTIVITY_SOURCE)?;
    admit(deployment, &request, limits)?;
    let model = ActivityExecutorModel::load_committed(scalar)?;
    if model.package().archive_digest() != request.expected_package_sha256 {
        return Err(Error::PackagePin);
    }
    let retained = RetainedFileImport::open(deployment, request.import_identity, limits.read, cx)?;
    if retained.manifest().format != "mjpeg" {
        return Err(Error::UnsupportedMedia);
    }
    let (frame_capsule, frame_digest) = source_capsule(deployment, &retained, request.segment)?;
    let (reference_capsule, reference_digest) =
        source_capsule(deployment, &retained, request.reference_segment)?;
    for capsule in [&frame_capsule, &reference_capsule] {
        if capsule.sensor_id != request.plan.sensor_id
            || capsule.stream_id != request.plan.stream_id
            || capsule.frame_count != 1
            || capsule.source_bytes > limits.decode.frame.maximum_bytes as u64
        {
            return Err(Error::Selection("original capsule scope or source size"));
        }
    }
    if reference_capsule.sequence >= frame_capsule.sequence {
        return Err(Error::Selection("original capsule order"));
    }
    refuse_mask(deployment, &request.plan)?;
    let source_budget = SourceReadBudget::new(limits.max_source_read_bytes);
    let mut chunks = VerifiedChunkCache::with_source_budget(Some(&source_budget));
    let frame_source =
        retained.read_segment_cached(deployment, request.segment, limits.read, cx, &mut chunks)?;
    let reference_source = retained.read_segment_cached(
        deployment,
        request.reference_segment,
        limits.read,
        cx,
        &mut chunks,
    )?;
    verify_custody(&frame_capsule, &frame_source)?;
    verify_custody(&reference_capsule, &reference_source)?;
    drop(chunks);
    checkpoint(cx, scalar, "recorded_activity:decode")?;
    let mut decode = DecodeBudget::new(limits.max_decode_work);
    let frame = decode_rgb(
        &frame_source,
        frame_capsule.source_digest.bytes(),
        request.plan.interpretation,
        limits.decode,
        &mut decode,
    )?;
    checkpoint(cx, scalar, "recorded_activity:reference")?;
    let reference = decode_rgb(
        &reference_source,
        reference_capsule.source_digest.bytes(),
        request.plan.interpretation,
        limits.decode,
        &mut decode,
    )?;
    checkpoint(cx, scalar, "recorded_activity:invoke")?;
    let (result, invocation) = model.invoke(
        &request.plan.sensor_id,
        ActivityFrameBinding {
            pixels: frame.pixels(),
            receipt: frame.receipt(),
            source_digest: frame_capsule.source_digest,
            capsule: &frame_capsule,
        },
        ActivityFrameBinding {
            pixels: reference.pixels(),
            receipt: reference.receipt(),
            source_digest: reference_capsule.source_digest,
            capsule: &reference_capsule,
        },
        &request.plan.policy,
        request.plan.execution,
        &request.plan.job_id,
        scalar,
    )?;
    checkpoint(cx, scalar, "recorded_activity:revalidate")?;
    let source_objects = [
        frame_source,
        reference_source,
        frame_capsule.try_canonical_bytes()?,
        reference_capsule.try_canonical_bytes()?,
        rgb_decode_receipt_bytes(&frame.receipt()),
        rgb_decode_receipt_bytes(&reference.receipt()),
    ];
    drop(frame);
    drop(reference);
    if ContentDigest::sha256(&source_objects[2]) != frame_digest
        || ContentDigest::sha256(&source_objects[3]) != reference_digest
    {
        return Err(Error::SourceChanged);
    }
    // Use a new cache, sharing the same allowance: source bytes changed during computation cannot
    // be hidden by the first pass's previously verified cached chunks.
    let mut final_chunks = VerifiedChunkCache::with_source_budget(Some(&source_budget));
    for (segment, original, capsule, digest) in [
        (
            request.segment,
            &source_objects[0],
            &frame_capsule,
            frame_digest,
        ),
        (
            request.reference_segment,
            &source_objects[1],
            &reference_capsule,
            reference_digest,
        ),
    ] {
        if retained.read_segment_cached(deployment, segment, limits.read, cx, &mut final_chunks)?
            != *original
            || source_capsule(deployment, &retained, segment)? != (capsule.clone(), digest)
        {
            return Err(Error::SourceChanged);
        }
    }
    drop(final_chunks);
    refuse_mask(deployment, &request.plan)?;
    let source_slot = slot(
        result.object_digest(),
        frame_digest,
        reference_digest,
        retained.manifest_digest(),
    )?;
    let mut children: Vec<_> = source_objects
        .iter()
        .map(|bytes| ContentDigest::sha256(bytes))
        .collect();
    children.sort_unstable();
    children.dedup();
    let manifest = ObjectManifest::new(
        source_slot.as_str(),
        children,
        Some(retained.manifest_digest()),
    )?;
    let mut result_children = vec![result.object_digest(), result.invocation_receipt_object];
    result_children.sort_unstable();
    result_children.dedup();
    let result_slot = retention_slot(result.object_digest())?;
    let result_manifest = ObjectManifest::new(result_slot.as_str(), result_children, None)?;
    let mut staged_input_bytes = 0_u64;
    for length in source_objects.iter().map(Vec::len).chain([
        manifest.canonical_bytes().len(),
        result_manifest.canonical_bytes().len(),
        result.canonical_bytes().len(),
        invocation.to_json_canonical().len(),
    ]) {
        staged_input_bytes = staged_input_bytes
            .checked_add(length as u64)
            .filter(|n| *n <= limits.max_staged_bytes)
            .ok_or(Error::Limit("complete publication input bytes"))?;
    }
    checkpoint(cx, scalar, STAGE_ACTIVITY_BEFORE_PUBLISH)?;
    if let Some(existing) = deployment.publisher().root(&source_slot) {
        if existing.root != manifest.root() || existing.state != LocalPublicationState::Durable {
            return Err(Error::SourceChanged);
        }
        // Existing publication means retry, not permission to repair damaged immutable roles.
        for bytes in &source_objects {
            let digest = ContentDigest::sha256(bytes);
            if deployment
                .publisher()
                .spool()
                .read_bounded(digest, bytes.len())?
                != *bytes
            {
                return Err(Error::SourceChanged);
            }
        }
        if deployment
            .publisher()
            .spool()
            .read_bounded(manifest.root(), manifest.canonical_bytes().len())?
            != manifest.canonical_bytes()
        {
            return Err(Error::SourceChanged);
        }
    } else {
        for bytes in &source_objects {
            checkpoint(cx, scalar, "recorded_activity:stage_role")?;
            if deployment.stage_payload(bytes)? != ContentDigest::sha256(bytes) {
                return Err(Error::SourceChanged);
            }
        }
    }
    let validity = CaptureInterval::new(
        frame_capsule
            .capture
            .earliest
            .min(reference_capsule.capture.earliest),
        frame_capsule
            .capture
            .latest
            .max(reference_capsule.capture.latest),
    )?;
    deployment.publish_and_commit(&source_slot, &manifest, validity, cx)?;
    checkpoint(cx, scalar, STAGE_ACTIVITY_RESULT)?;
    let output =
        retain_executor_result(deployment, &result, &invocation, frame_capsule.capture, cx)?;
    Ok(RecordedActivityReceipt {
        retained: output,
        source_slot,
        source_root: manifest.root(),
        import_identity: retained.import_identity(),
        import_root: retained.import_root(),
        reference_segment: request.reference_segment,
        segment: request.segment,
        reference_capsule: reference_digest,
        frame_capsule: frame_digest,
        plan: request.plan,
        package_sha256: model.package().archive_digest(),
        package_root: model.package().manifest_digest(),
        source_read_bytes: source_budget.used(),
        decode_work: decode.used(),
        staged_input_bytes,
        final_anchor: deployment.current_anchor().clone(),
    })
}

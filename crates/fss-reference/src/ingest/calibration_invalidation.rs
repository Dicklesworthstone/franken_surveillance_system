#![forbid(unsafe_code)]
//! Durable owner withdrawal of an exact current calibration adoption (FSS-091).
//!
//! A preview binds the current adoption, bounded reason, optional retained same-sensor capsule,
//! and deployment/restore domain. Consuming that exact approval appends one immutable authority
//! record and its approval witness. It never edits an adoption receipt or automatically diagnoses
//! camera movement. All existing adoption currency consumers see the withdrawal on restart.
//!
//! Optional evidence is checked before first publication. Later source deletion cannot undo
//! owner authority: historical loading verifies the prior capsule ledger reference, while the
//! invalidation and approval receipts themselves must remain readable. Recovery requires a new
//! calibration identity and at least one strictly newer camera generation, with neither lower.

use std::collections::BTreeMap;
use std::fmt;

use fss_core::{
    BatchId, CanonicalDecode, CaptureInterval, ContentDigest, ContractError, EvidenceDelta,
    EvidenceDeltaBatch, Plane, SensorCapsule, SensorId, TimestampNs,
};

use super::calibration_adoption::{AdoptionError, RetainedAdoption, retained_adoptions};
use crate::reference_deployment::{FAMILY_CALIBRATION_INVALIDATION, FAMILY_SENSOR_CAPSULE};
use crate::{ReferenceDeployment, ReferenceError, ReplayCx};

mod codec;
pub use codec::{
    INVALIDATION_APPROVAL_DOMAIN, INVALIDATION_CLAIM, INVALIDATION_OBJECT_PREFIX,
    INVALIDATION_RECEIPT_DOMAIN, InvalidationCodecError, InvalidationReason, InvalidationReceipt,
    MAX_INVALIDATION_APPROVAL_BYTES, MAX_INVALIDATION_RECEIPT_BYTES, RetainedInvalidation,
    approval_bytes, approval_digest, authority_domain, bind_recovery_approval,
    invalidation_object_id,
};

/// Bound on immutable invalidations reconstructed in one retained authority prefix.
pub const MAX_RETAINED_INVALIDATIONS: usize = 65_536;
/// Sensor capsule metadata bound; source pixels are not read by owner invalidation.
pub const MAX_INVALIDATION_EVIDENCE_BYTES: usize = 4096;

/// Exact owner request. The target is always explicit; a later adoption cannot be selected silently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidationRequest {
    /// Property-local camera handle of the current adoption.
    pub camera_handle: u64,
    /// Exact adoption receipt reviewed by the owner.
    pub adoption_digest: ContentDigest,
    /// Bounded owner diagnosis.
    pub reason: InvalidationReason,
    /// Optional retained same-sensor capsule payload digest, not an import or arbitrary blob.
    pub evidence: Option<ContentDigest>,
}

/// Whether a withdrawal is a preview, a new commit, or an exact durable retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidationStatus {
    /// Read-only preview awaiting exact owner approval.
    Proposed,
    /// This call retained the immutable withdrawal.
    Retained,
    /// The exact withdrawal was already retained; no new write occurred.
    AlreadyInvalidated,
}

impl InvalidationStatus {
    /// Stable report token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Retained => "retained",
            Self::AlreadyInvalidated => "already_invalidated",
        }
    }
}

/// Reviewable immutable receipt and its exact approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invalidation {
    /// Exact receipt that would be or has been retained.
    pub receipt: InvalidationReceipt,
    /// Exact approval over every receipt field and its deployment domain.
    pub approval: ContentDigest,
    /// Publication disposition.
    pub status: InvalidationStatus,
}

/// A refusal never restores calibration currency or stages a substitute request.
#[derive(Debug)]
pub enum InvalidationError {
    /// Invalid caller input.
    InvalidInput(&'static str),
    /// The explicit target is absent or was superseded.
    TargetNotCurrent {
        /// Requested property-local camera handle.
        camera_handle: u64,
        /// Requested adoption receipt.
        adoption_digest: ContentDigest,
    },
    /// An existing withdrawal cannot be edited by changing its reason or evidence.
    AlreadyInvalidated {
        /// Requested property-local camera handle.
        camera_handle: u64,
        /// Existing immutable withdrawal receipt.
        invalidation: ContentDigest,
    },
    /// Optional evidence is not readable retained same-sensor capsule metadata.
    EvidenceInvalid(&'static str),
    /// The approval did not bind this exact preview.
    StaleApproval(ContentDigest),
    /// Existing adoption or invalidation custody failed verification.
    Adoption(Box<AdoptionError>),
    /// Invalid immutable receipt.
    Codec(InvalidationCodecError),
    /// Invalid underlying canonical field.
    Contract(ContractError),
    /// Retention or publication failed.
    Reference(Box<ReferenceError>),
    /// Cancellation before a durable withdrawal.
    Cancelled,
}

impl InvalidationError {
    /// Existing calibration-invalid registry identity; the typed variant preserves the cause.
    #[must_use]
    pub const fn stable_id(&self) -> &'static str {
        "ERR-CALIBRATION-INVALID-001"
    }
}

impl fmt::Display for InvalidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(reason) => write!(f, "invalid calibration withdrawal: {reason}"),
            Self::TargetNotCurrent {
                camera_handle,
                adoption_digest,
            } => write!(
                f,
                "camera {camera_handle}: adoption {adoption_digest} is not the current retained adoption"
            ),
            Self::AlreadyInvalidated {
                camera_handle,
                invalidation,
            } => write!(
                f,
                "camera {camera_handle}: immutable invalidation {invalidation} already withdraws this adoption"
            ),
            Self::EvidenceInvalid(reason) => {
                write!(f, "calibration invalidation evidence: {reason}")
            }
            Self::StaleApproval(approval) => write!(
                f,
                "calibration invalidation approval {approval} does not match the current request"
            ),
            Self::Adoption(error) => write!(f, "calibration invalidation authority: {error}"),
            Self::Codec(error) => write!(f, "{error}"),
            Self::Contract(error) => write!(f, "calibration invalidation contract: {error}"),
            Self::Reference(error) => write!(f, "calibration invalidation retention: {error}"),
            Self::Cancelled => f.write_str("calibration invalidation cancelled before publication"),
        }
    }
}
impl std::error::Error for InvalidationError {}
impl From<AdoptionError> for InvalidationError {
    fn from(value: AdoptionError) -> Self {
        Self::Adoption(Box::new(value))
    }
}
impl From<InvalidationCodecError> for InvalidationError {
    fn from(value: InvalidationCodecError) -> Self {
        Self::Codec(value)
    }
}
impl From<ContractError> for InvalidationError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}
impl From<ReferenceError> for InvalidationError {
    fn from(value: ReferenceError) -> Self {
        Self::Reference(Box::new(value))
    }
}

fn evidence_was_retained(
    batches: &[EvidenceDeltaBatch],
    evidence: ContentDigest,
    before_sequence: Option<u64>,
) -> bool {
    batches.iter().any(|batch| {
        before_sequence.is_none_or(|before| batch.new_anchor.commit_sequence < before)
            && batch.deltas.iter().any(|delta| {
                delta.family == FAMILY_SENSOR_CAPSULE
                    && delta.plane == Plane::Authority
                    && delta.prior_generation.is_none()
                    && delta.new_generation == 1
                    && delta.payload_digest == evidence
                    && batch.children.contains(&evidence)
            })
    })
}

fn verify_evidence(
    deployment: &ReferenceDeployment,
    evidence: ContentDigest,
    sensor: &SensorId,
) -> Result<(), InvalidationError> {
    codec::sha256_only(evidence)?;
    if !evidence_was_retained(deployment.ledger().batches(), evidence, None) {
        return Err(InvalidationError::EvidenceInvalid(
            "no retained sensor capsule has this payload",
        ));
    }
    let bytes = deployment
        .publisher()
        .spool()
        .read_bounded(evidence, MAX_INVALIDATION_EVIDENCE_BYTES)
        .map_err(|_| {
            InvalidationError::EvidenceInvalid(
                "capsule is unreadable or exceeds its metadata bound",
            )
        })?;
    if ContentDigest::sha256(&bytes) != evidence {
        return Err(InvalidationError::EvidenceInvalid(
            "capsule authority digest mismatch",
        ));
    }
    let capsule = SensorCapsule::from_canonical_bytes(&bytes).map_err(|_| {
        InvalidationError::EvidenceInvalid("payload is not canonical sensor capsule metadata")
    })?;
    if capsule.sensor_id != *sensor {
        return Err(InvalidationError::EvidenceInvalid(
            "capsule belongs to a different adopted sensor",
        ));
    }
    Ok(())
}

/// Read-only exact-current preview. Unrelated authority appends do not change this approval.
pub fn preview_invalidation(
    deployment: &ReferenceDeployment,
    request: &InvalidationRequest,
) -> Result<Invalidation, InvalidationError> {
    if request.camera_handle == 0 {
        return Err(InvalidationError::InvalidInput(
            "camera handle must be nonzero",
        ));
    }
    codec::sha256_only(request.adoption_digest)?;
    if let Some(evidence) = request.evidence {
        codec::sha256_only(evidence)?;
    }
    let history = retained_adoptions(deployment)?;
    let current = history
        .get(&request.camera_handle)
        .and_then(|chain| chain.last())
        .filter(|current| current.digest == request.adoption_digest)
        .ok_or(InvalidationError::TargetNotCurrent {
            camera_handle: request.camera_handle,
            adoption_digest: request.adoption_digest,
        })?;
    if let Some(retained) = &current.invalidation {
        if retained.receipt.reason != request.reason
            || retained.receipt.evidence != request.evidence
        {
            return Err(InvalidationError::AlreadyInvalidated {
                camera_handle: request.camera_handle,
                invalidation: retained.digest,
            });
        }
        return Ok(Invalidation {
            receipt: retained.receipt.clone(),
            approval: approval_digest(&retained.receipt),
            status: InvalidationStatus::AlreadyInvalidated,
        });
    }
    if let Some(evidence) = request.evidence {
        verify_evidence(deployment, evidence, &current.receipt.sensor_id)?;
    }
    let anchor = deployment.current_anchor();
    let receipt = InvalidationReceipt {
        authority_domain: authority_domain(&anchor.site_lineage, anchor.ledger_epoch),
        adoption: current.receipt.adoption,
        adoption_digest: current.digest,
        camera_handle: current.receipt.camera_handle,
        sensor_id: current.receipt.sensor_id.clone(),
        calibration_digest: current.receipt.calibration_digest,
        intrinsics_generation: current.receipt.intrinsics_generation,
        extrinsics_generation: current.receipt.extrinsics_generation,
        reason: request.reason,
        evidence: request.evidence,
    };
    receipt.validate()?;
    Ok(Invalidation {
        approval: approval_digest(&receipt),
        receipt,
        status: InvalidationStatus::Proposed,
    })
}

/// Consume only the exact current preview and append one immutable authority withdrawal.
/// Approval and cancellation are checked before staging. The reserved publication path
/// retains the immutable delta and its exact approval witness through the existing ledger.
pub fn invalidate(
    deployment: &mut ReferenceDeployment,
    request: &InvalidationRequest,
    approval: ContentDigest,
    cx: &ReplayCx,
) -> Result<Invalidation, InvalidationError> {
    cx.checkpoint("calibration_invalidation:check")
        .map_err(|_| InvalidationError::Cancelled)?;
    let preview = preview_invalidation(deployment, request)?;
    if approval != preview.approval {
        return Err(InvalidationError::StaleApproval(approval));
    }
    if preview.status == InvalidationStatus::AlreadyInvalidated {
        return Ok(preview);
    }
    cx.checkpoint("calibration_invalidation:retain")
        .map_err(|_| InvalidationError::Cancelled)?;
    let payload = deployment.stage_payload(&preview.receipt.to_bytes())?;
    let witness = deployment.stage_payload(&approval_bytes(&preview.receipt))?;
    if payload != preview.receipt.digest() || witness != approval {
        return Err(InvalidationError::InvalidInput(
            "staged receipt or approval digest mismatch",
        ));
    }
    let identity = approval.to_string();
    let identity = identity
        .strip_prefix("sha256:")
        .ok_or(ContractError::InvalidDigest)?;
    let delta = EvidenceDelta {
        delta_id: format!("delta:calibration-invalidation:{identity}"),
        family: FAMILY_CALIBRATION_INVALIDATION.to_owned(),
        object_id: invalidation_object_id(request.adoption_digest)?,
        prior_generation: None,
        new_generation: 1,
        validity: CaptureInterval::new(TimestampNs(0), TimestampNs(i128::from(i64::MAX)))?,
        plane: Plane::Authority,
        payload_digest: payload,
        witness_digest: Some(witness),
        operation_id: None,
    };
    let mut children = vec![payload, witness, preview.receipt.adoption_digest];
    if let Some(evidence) = preview.receipt.evidence {
        children.push(evidence);
    }
    deployment.append_calibration_invalidation_batch(
        BatchId::parse(format!("batch:calibration-invalidation:{identity}"))?,
        vec![delta],
        children,
        cx,
    )?;
    cx.checkpoint_post_commit("calibration_invalidation:retained");
    Ok(Invalidation {
        status: InvalidationStatus::Retained,
        ..preview
    })
}

/// Whether a replacement can recover an invalidated generation without rollback or relabeling.
pub(crate) fn replacement_is_newer(
    previous: &RetainedAdoption,
    next: &super::calibration_adoption::AdoptionReceipt,
) -> bool {
    next.calibration_digest != previous.receipt.calibration_digest
        && next.intrinsics_generation >= previous.receipt.intrinsics_generation
        && next.extrinsics_generation >= previous.receipt.extrinsics_generation
        && (next.intrinsics_generation > previous.receipt.intrinsics_generation
            || next.extrinsics_generation > previous.receipt.extrinsics_generation)
}

/// Attach verified immutable withdrawals only from the caller's committed prefix. Optional
/// source custody is not reread: its later deletion never resurrects an owner-withdrawn adoption.
pub(crate) fn attach_invalidations(
    batches: &[EvidenceDeltaBatch],
    adoptions: &mut BTreeMap<u64, Vec<RetainedAdoption>>,
    read_object: &mut impl FnMut(ContentDigest, usize) -> Result<Vec<u8>, AdoptionError>,
) -> Result<(), AdoptionError> {
    let bad = AdoptionError::InvalidRecord;
    let mut count = 0_usize;
    for batch in batches {
        for delta in &batch.deltas {
            if delta.family != FAMILY_CALIBRATION_INVALIDATION {
                if delta
                    .object_id
                    .as_str()
                    .starts_with(INVALIDATION_OBJECT_PREFIX)
                {
                    return Err(bad("invalidation object in a different authority family"));
                }
                continue;
            }
            count += 1;
            if count > MAX_RETAINED_INVALIDATIONS {
                return Err(bad(
                    "calibration invalidation history exceeds its read bound",
                ));
            }
            if delta.plane != Plane::Authority
                || delta.prior_generation.is_some()
                || delta.new_generation != 1
                || delta.operation_id.is_some()
            {
                return Err(bad("invalid calibration invalidation authority delta"));
            }
            let bytes = read_object(delta.payload_digest, MAX_INVALIDATION_RECEIPT_BYTES)?;
            let receipt = InvalidationReceipt::from_bytes(&bytes, delta.payload_digest)
                .map_err(|_| bad("invalid calibration invalidation receipt"))?;
            let approval = approval_digest(&receipt);
            if delta.object_id != invalidation_object_id(receipt.adoption_digest)?
                || delta.witness_digest != Some(approval)
                || receipt.authority_domain
                    != authority_domain(
                        &batch.new_anchor.site_lineage,
                        batch.new_anchor.ledger_epoch,
                    )
                || !batch.children.contains(&delta.payload_digest)
                || !batch.children.contains(&approval)
                || !batch.children.contains(&receipt.adoption_digest)
            {
                return Err(bad("calibration invalidation authority binding mismatch"));
            }
            let approved = read_object(approval, MAX_INVALIDATION_APPROVAL_BYTES)?;
            if approved != approval_bytes(&receipt) || ContentDigest::sha256(&approved) != approval
            {
                return Err(bad("calibration invalidation approval witness mismatch"));
            }
            if let Some(evidence) = receipt.evidence
                && (!batch.children.contains(&evidence)
                    || !evidence_was_retained(
                        batches,
                        evidence,
                        Some(batch.new_anchor.commit_sequence),
                    ))
            {
                return Err(bad(
                    "calibration invalidation evidence was not previously retained",
                ));
            }
            let history = adoptions
                .get_mut(&receipt.camera_handle)
                .ok_or(bad("invalidation targets an unadopted camera"))?;
            let index = history
                .iter()
                .position(|a| a.digest == receipt.adoption_digest)
                .ok_or(bad("invalidation targets an unknown adoption"))?;
            let sequence = batch.new_anchor.commit_sequence;
            if sequence <= history[index].committed_sequence
                || history
                    .get(index + 1)
                    .is_some_and(|next| sequence >= next.committed_sequence)
            {
                return Err(bad(
                    "invalidation did not target the current adoption at its commit",
                ));
            }
            let target = &mut history[index];
            if target.invalidation.is_some()
                || target.receipt.adoption != receipt.adoption
                || target.receipt.camera_handle != receipt.camera_handle
                || target.receipt.sensor_id != receipt.sensor_id
                || target.receipt.calibration_digest != receipt.calibration_digest
                || target.receipt.intrinsics_generation != receipt.intrinsics_generation
                || target.receipt.extrinsics_generation != receipt.extrinsics_generation
            {
                return Err(bad("invalidation target receipt binding mismatch"));
            }
            target.invalidation = Some(RetainedInvalidation {
                receipt,
                digest: delta.payload_digest,
                committed_sequence: sequence,
            });
        }
    }
    for history in adoptions.values() {
        for pair in history.windows(2) {
            if pair[0].invalidation.is_some() && !replacement_is_newer(&pair[0], &pair[1].receipt) {
                return Err(bad(
                    "invalidated adoption recovered without a newer calibration generation",
                ));
            }
        }
    }
    Ok(())
}

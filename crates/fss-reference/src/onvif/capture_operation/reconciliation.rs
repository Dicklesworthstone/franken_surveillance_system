#![forbid(unsafe_code)]
//! Terminal capture obligations from exact retained control custody, with no network I/O.

use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, EffectState, OperationId, TimestampNs,
};

use super::{
    CaptureOperationError, CaptureOperationInspection, checkpoint, inspection, owner_principal,
    valid_digest, verify_history,
};
use crate::onvif::control::{
    RetainedSubscription, RetainedUnsubscribe, RetainedUnsubscribeOutcome,
};
use crate::{ReferenceDeployment, ReplayAdmission, ReplayCx};

/// Proof binds one original operation, its physical stores and its exact cleanup custody.
pub const CLEANUP_PROOF_DOMAIN: &str = "fss.onvif_capture_cleanup_proof.v1";
/// Last admission after control custody and original preparation have been revalidated.
pub const STAGE_CLEANUP_REVALIDATED: &str = "onvif_capture_operation:cleanup_revalidated";
/// Crash/cancellation cut after the historical Create acceptance has been recorded.
pub const STAGE_CLEANUP_ACCEPTED: &str = "onvif_capture_operation:cleanup_accepted";
/// Crash/cancellation cut after cleanup observation, before terminal verification.
pub const STAGE_CLEANUP_OBSERVED: &str = "onvif_capture_operation:cleanup_observed";
/// Post-commit checkpoint; late refusal never erases the returned terminal receipt.
pub const STAGE_CLEANUP_RECONCILED: &str = "onvif_capture_operation:cleanup_reconciled";

/// Exact retained terminal selector. Caller-supplied hashes are always reopened and verified.
/// A malformed, rejected, unrelated or deleted source cannot discharge an obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureCleanupEvidence {
    /// A successful v1 Unsubscribe marker with its complete Create/source closure.
    Unsubscribed {
        /// Canonical record identity.
        identity: ContentDigest,
        /// Independently selected publication root.
        root: ContentDigest,
    },
    /// A successful correlated raw outcome, including one whose final marker was interrupted.
    Outcome {
        /// Canonical raw-outcome identity.
        identity: ContentDigest,
        /// Independently selected publication root.
        root: ContentDigest,
    },
}

struct VerifiedCleanup {
    subscription: RetainedSubscription,
    identity: ContentDigest,
    root: ContentDigest,
    source: ContentDigest,
    received_at: TimestampNs,
    kind: u8,
}

impl CaptureCleanupEvidence {
    fn open(
        self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx<impl ReplayAdmission>,
    ) -> Result<VerifiedCleanup, CaptureOperationError> {
        let (identity, root) = match self {
            Self::Unsubscribed { identity, root } | Self::Outcome { identity, root } => {
                (identity, root)
            }
        };
        if !valid_digest(identity) || !valid_digest(root) {
            return Err(CaptureOperationError::InvalidBinding);
        }
        match self {
            Self::Unsubscribed { .. } => {
                let value = RetainedUnsubscribe::open(deployment, identity, Some(root), cx)
                    .map_err(|_| CaptureOperationError::Custody)?;
                Ok(VerifiedCleanup {
                    subscription: value.subscription().clone(),
                    identity,
                    root,
                    source: value.source_digest(),
                    received_at: value.binding().receive_interval.latest,
                    kind: 1,
                })
            }
            Self::Outcome { .. } => {
                let value = RetainedUnsubscribeOutcome::open(deployment, identity, Some(root), cx)
                    .map_err(|_| CaptureOperationError::Custody)?;
                if !value.success_observed() {
                    return Err(CaptureOperationError::Custody);
                }
                Ok(VerifiedCleanup {
                    subscription: value.intent().subscription().clone(),
                    identity,
                    root,
                    source: value.source_digest(),
                    received_at: value.receive_interval().latest,
                    kind: 2,
                })
            }
        }
    }
}

fn proof(
    deployment: &ReferenceDeployment,
    operation: &CaptureOperationInspection,
    cleanup: &VerifiedCleanup,
) -> Result<ContentDigest, CaptureOperationError> {
    let prepared = deployment
        .effects()
        .effect_journal()
        .prepared_record(&operation.internal_operation_id)?;
    let mut e = CanonicalEncoder::new();
    e.text(CLEANUP_PROOF_DOMAIN);
    e.text(deployment.site_lineage());
    e.digest(
        deployment
            .ledger()
            .store_pin()
            .ok_or(CaptureOperationError::Custody)?,
    );
    e.digest(
        deployment
            .effects()
            .store_pin()
            .ok_or(CaptureOperationError::Custody)?,
    );
    e.digest(prepared.canonical_digest());
    operation.receipt.authority.encode_canonical(&mut e);
    e.digest(cleanup.subscription.intent_identity());
    e.digest(cleanup.subscription.intent().publication_root());
    e.digest(cleanup.subscription.identity());
    e.digest(cleanup.subscription.publication_root());
    e.u8(cleanup.kind);
    e.digest(cleanup.identity);
    e.digest(cleanup.root);
    e.digest(cleanup.source);
    Ok(ContentDigest::sha256(&e.finish_checked()?))
}

/// Reconcile one bound capture operation from an exact successful cleanup receipt.
///
/// This operation performs only local custody reads and durable journal transitions.
/// It needs the original admitted owner and never recovers network, credential or
/// Create authority. Legacy unbound reservations and never-committed reservations
/// refuse. A retained raw success suffices when final marker publication failed.
///
/// `now` supplies fresh, explicitly authorized deployment-clock observations for
/// each append. A crash/refusal between acceptance, observation and verification
/// leaves resumable evidence; an exact retry uses the same proof and never sends.
/// A verified exact retry writes nothing and does not request another clock sample.
pub fn reconcile_cleanup(
    deployment: &mut ReferenceDeployment,
    owner_operation_id: &OperationId,
    evidence: CaptureCleanupEvidence,
    minimum_journal_root: Option<ContentDigest>,
    mut now: impl FnMut() -> Result<TimestampNs, CaptureOperationError>,
    cx: &ReplayCx<impl ReplayAdmission>,
) -> Result<CaptureOperationInspection, CaptureOperationError> {
    let roots = verify_history(deployment, true, cx)?;
    if minimum_journal_root
        .is_some_and(|minimum| !valid_digest(minimum) || !roots.contains(&minimum))
    {
        return Err(CaptureOperationError::Minimum);
    }
    let operation = inspection(deployment, owner_operation_id, None)?;
    if operation.receipt.authority.principal != owner_principal(cx.io_authority().principal())? {
        return Err(CaptureOperationError::Authority);
    }
    let expected_intent = operation
        .create_intent
        .ok_or(CaptureOperationError::Custody)?;
    if !matches!(
        operation.receipt.state,
        EffectState::Committed
            | EffectState::AdapterAccepted
            | EffectState::Indeterminate
            | EffectState::Observed
            | EffectState::Verified
    ) {
        return Err(CaptureOperationError::Custody);
    }
    let cleanup = evidence.open(deployment, cx)?;
    if cleanup.subscription.intent_identity() != expected_intent {
        return Err(CaptureOperationError::Custody);
    }
    let proof = proof(deployment, &operation, &cleanup)?;
    match operation.receipt.state {
        EffectState::Observed | EffectState::Verified
            if operation.receipt.result_digest != Some(proof) =>
        {
            return Err(CaptureOperationError::Custody);
        }
        EffectState::AdapterAccepted
            if operation.receipt.result_digest != Some(cleanup.subscription.publication_root()) =>
        {
            return Err(CaptureOperationError::Custody);
        }
        _ => {}
    }
    checkpoint(cx, STAGE_CLEANUP_REVALIDATED)?;
    // Recheck physical identities and the full durable prefix after the last
    // custody read and callback, before any append can discharge this obligation.
    verify_history(deployment, true, cx)?;
    if inspection(deployment, owner_operation_id, None)?.receipt != operation.receipt {
        return Err(CaptureOperationError::Custody);
    }
    if operation.receipt.state == EffectState::Verified {
        return inspection(deployment, owner_operation_id, None);
    }
    let op = &operation.internal_operation_id;
    let next_time = |now: &mut dyn FnMut() -> Result<TimestampNs, CaptureOperationError>| {
        let at = now()?;
        if at < cleanup.received_at {
            return Err(CaptureOperationError::InvalidBinding);
        }
        Ok(at)
    };
    if operation.receipt.state == EffectState::Committed {
        let at = next_time(&mut now)?;
        checkpoint(cx, "onvif_capture_operation:cleanup_accept")?;
        deployment.effects_mut().transition(
            op,
            EffectState::AdapterAccepted,
            at,
            Some(cleanup.subscription.publication_root()),
            None,
        )?;
        checkpoint(cx, STAGE_CLEANUP_ACCEPTED)?;
    }
    if operation.receipt.state != EffectState::Observed {
        let at = next_time(&mut now)?;
        checkpoint(cx, "onvif_capture_operation:cleanup_observe")?;
        deployment
            .effects_mut()
            .transition(op, EffectState::Observed, at, Some(proof), None)?;
        checkpoint(cx, STAGE_CLEANUP_OBSERVED)?;
    }
    let at = next_time(&mut now)?;
    checkpoint(cx, "onvif_capture_operation:cleanup_verify")?;
    deployment.effects_mut().reconcile_verified(op, proof, at)?;
    let result = inspection(deployment, owner_operation_id, None)?;
    cx.checkpoint_post_commit(STAGE_CLEANUP_RECONCILED);
    Ok(result)
}

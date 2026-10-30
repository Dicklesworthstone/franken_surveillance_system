#![forbid(unsafe_code)]
//! Journal-local authentication of a completed native report transition for a case citation.
//!
//! The native evaluator remains the source owner. These checks prove exactly which retained
//! Publish/Release transition completed; replay neither rereads source nor asserts current custody.

use super::*;

/// Exact retained supervisor state at one successful native publication or revalidation.
/// These fields are internal replay material, never a caller-provided source capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::agent_session::checkpoint::journal) struct ProbeStatePin {
    pub principal: PrincipalId,
    pub session: SessionId,
    pub subscription: String,
    pub configuration: ContentDigest,
    pub supervisions: ContentDigest,
    pub subscription_state: ContentDigest,
    pub checkpoint: ContentDigest,
    pub command: ContentDigest,
    pub pending: ContentDigest,
    pub report: ContentDigest,
    pub payload: ContentDigest,
    pub payload_bytes: u64,
    pub report_anchor: LedgerAnchor,
    pub attempts_reserved: u32,
    pub active_window_count: Option<u32>,
    pub replayed: bool,
    pub observed_at: TimestampNs,
}

/// Recover only a completed report transition, and bind it to the semantically replayed state.
pub(in crate::agent_session::checkpoint::journal) fn pin_transition(
    bytes: &[u8],
    state: &SupervisionState,
) -> std::result::Result<ProbeStatePin, DurableSessionError> {
    let record = codec::decode_record(bytes)?;
    let replayed = match &record.command {
        Command::Publish { .. } => false,
        Command::Release { .. } => true,
        _ => return Err(DurableSessionError::InvalidHistory),
    };
    if record.after_state != state.digest() {
        return Err(DurableSessionError::InvalidHistory);
    }
    let subscription = state
        .subscriptions
        .get(&(
            record.session.clone(),
            record.command.subscription().to_owned(),
        ))
        .ok_or(DurableSessionError::InvalidHistory)?;
    let pending = subscription
        .pending
        .as_ref()
        .ok_or(DurableSessionError::InvalidHistory)?;
    if subscription.reservation.is_some() {
        return Err(DurableSessionError::InvalidHistory);
    }
    let pin = ProbeStatePin {
        principal: record.principal.clone(),
        session: record.session.clone(),
        subscription: record.command.subscription().to_owned(),
        configuration: subscription.registration.configuration_digest,
        supervisions: record.after_state,
        subscription_state: subscription.digest(),
        checkpoint: record.session_digest,
        command: ContentDigest::sha256(bytes),
        pending: pending.receipt,
        report: pending.report_receipt,
        payload: pending.payload_digest,
        payload_bytes: pending.payload.len() as u64,
        report_anchor: pending.anchor.clone(),
        attempts_reserved: subscription.attempts_reserved,
        active_window_count: pending.active_window_count,
        replayed,
        observed_at: record.now,
    };
    verify_transition(bytes, &pin)?;
    Ok(pin)
}

/// Authenticate the actual immediately preceding command, not merely a record-kind label.
pub(in crate::agent_session::checkpoint::journal) fn verify_transition(
    bytes: &[u8],
    pin: &ProbeStatePin,
) -> std::result::Result<(), DurableSessionError> {
    let record = codec::decode_record(bytes)?;
    if ContentDigest::sha256(bytes) != pin.command
        || record.principal != pin.principal
        || record.session != pin.session
        || record.command.subscription() != pin.subscription
        || record.session_digest != pin.checkpoint
        || record.after_state != pin.supervisions
        || record.before_state == record.after_state
        || record.now != pin.observed_at
    {
        return Err(DurableSessionError::InvalidHistory);
    }
    match record.command {
        Command::Publish {
            payload,
            report_receipt,
            ..
        } if !pin.replayed
            && ContentDigest::sha256(&payload) == pin.payload
            && payload.len() as u64 == pin.payload_bytes
            && report_receipt == pin.report =>
        {
            Ok(())
        }
        Command::Release { receipt, .. } if pin.replayed && receipt == pin.pending => Ok(()),
        _ => Err(DurableSessionError::InvalidHistory),
    }
}

/// Check the exact live registration and full authority projection without reserving source work.
pub(in crate::agent_session::checkpoint::journal) fn admit_subscription<'a>(
    memory: &mut ReferenceSessionStore,
    state: &'a SupervisionState,
    principal: &PrincipalId,
    session: &SessionId,
    subscription: &str,
    now: TimestampNs,
) -> std::result::Result<&'a SupervisionSubscription, DurableSessionError> {
    if !label(subscription) {
        return Err(DurableSessionError::InvalidHistory);
    }
    let (authority_digest, _) = authority(memory, principal, session, now)
        .map_err(|_| DurableSessionError::InvalidHistory)?;
    let current = state
        .subscriptions
        .get(&(session.clone(), subscription.to_owned()))
        .ok_or(DurableSessionError::InvalidHistory)?;
    if current.authority_digest != authority_digest {
        return Err(DurableSessionError::InvalidHistory);
    }
    Ok(current)
}

/// Replay authentication retains all work, source inventory, pending, schedule and authority pins.
pub(in crate::agent_session::checkpoint::journal) fn verify_state<'a>(
    memory: &mut ReferenceSessionStore,
    state: &'a SupervisionState,
    pin: &ProbeStatePin,
) -> std::result::Result<&'a SupervisionSubscription, DurableSessionError> {
    if state.digest() != pin.supervisions {
        return Err(DurableSessionError::InvalidHistory);
    }
    let current = admit_subscription(
        memory,
        state,
        &pin.principal,
        &pin.session,
        &pin.subscription,
        pin.observed_at,
    )?;
    let pending = current
        .pending
        .as_ref()
        .ok_or(DurableSessionError::InvalidHistory)?;
    if current.digest() != pin.subscription_state
        || current.registration.configuration_digest != pin.configuration
        || current.reservation.is_some()
        || current.attempts_reserved != pin.attempts_reserved
        || pending.receipt != pin.pending
        || pending.report_receipt != pin.report
        || pending.payload_digest != pin.payload
        || pending.payload.len() as u64 != pin.payload_bytes
        || pending.anchor != pin.report_anchor
        || pending.active_window_count != pin.active_window_count
        || pending.active_window_count != current.active_window_count()
    {
        return Err(DurableSessionError::InvalidHistory);
    }
    Ok(current)
}
